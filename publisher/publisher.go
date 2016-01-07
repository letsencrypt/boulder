// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package publisher

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	ct "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/google/certificate-transparency/go"
	ctClient "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/google/certificate-transparency/go/client"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

// Log contains the CT client and signature verifier for a particular CT log
type Log struct {
	client   *ctClient.LogClient
	verifier *ct.SignatureVerifier
}

// NewLog returns an initialized Log struct
func NewLog(uri, b64PK string) (*Log, error) {
	if strings.HasSuffix(uri, "/") {
		uri = uri[0 : len(uri)-2]
	}
	client := ctClient.New(uri)

	pkBytes, err := base64.StdEncoding.DecodeString(b64PK)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode base64 log public key")
	}
	pk, err := x509.ParsePKIXPublicKey(pkBytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse log public key")
	}

	verifier, err := ct.NewSignatureVerifier(pk)
	if err != nil {
		return nil, err
	}

	return &Log{client, verifier}, nil
}

type ctSubmissionRequest struct {
	Chain []string `json:"chain"`
}

// PublisherImpl defines a Publisher
type PublisherImpl struct {
	log          *blog.AuditLogger
	client       *http.Client
	issuerBundle []ct.ASN1Cert
	ctLogs       []*Log

	SA core.StorageAuthority
}

// NewPublisherImpl creates a Publisher that will submit certificates
// to any CT logs configured in CTConfig
func NewPublisherImpl(bundle []ct.ASN1Cert, logs []*Log) (pub PublisherImpl) {
	logger := blog.GetAuditLogger()
	logger.Notice("Publisher Authority Starting")

	pub.issuerBundle = bundle
	pub.log = logger
	pub.ctLogs = logs

	return
}

// SubmitToCT will submit the certificate represented by certDER to any CT
// logs configured in pub.CT.Logs
func (pub *PublisherImpl) SubmitToCT(der []byte) error {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		pub.log.Audit(fmt.Sprintf("Failed to parse certificate: %s", err))
		return err
	}

	chain := append([]ct.ASN1Cert{der}, pub.issuerBundle...)
	for _, ctLog := range pub.ctLogs {
		sct, err := ctLog.client.AddChain(chain)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			pub.log.Audit(fmt.Sprintf("Failed to submit certificate to CT log: %s", err))
			continue
		}

		err = ctLog.verifier.VerifySCTSignature(*sct, ct.LogEntry{
			Leaf: ct.MerkleTreeLeaf{
				LeafType: ct.TimestampedEntryLeafType,
				TimestampedEntry: ct.TimestampedEntry{
					X509Entry: ct.ASN1Cert(der),
					EntryType: ct.X509LogEntryType,
				},
			},
		})
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			pub.log.Audit(fmt.Sprintf("Failed to verify SCT receipt: %s", err))
			continue
		}

		internalSCT, err := sctToInternal(sct, core.SerialToString(cert.SerialNumber))
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			pub.log.Audit(fmt.Sprintf("Failed to convert SCT receipt: %s", err))
			continue
		}

		err = pub.SA.AddSCTReceipt(internalSCT)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			pub.log.Audit(fmt.Sprintf("Failed to store SCT receipt in database: %s", err))
			continue
		}
	}

	return nil
}

func sctToInternal(sct *ct.SignedCertificateTimestamp, serial string) (core.SignedCertificateTimestamp, error) {
	sig, err := ct.MarshalDigitallySigned(sct.Signature)
	if err != nil {
		return core.SignedCertificateTimestamp{}, err
	}
	return core.SignedCertificateTimestamp{
		CertificateSerial: serial,
		SCTVersion:        uint8(sct.SCTVersion),
		LogID:             sct.LogID.Base64String(),
		Timestamp:         sct.Timestamp,
		Extensions:        sct.Extensions,
		Signature:         sig,
	}, nil
}
