// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package publisher

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	ct "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/google/certificate-transparency/go"
	ctClient "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/google/certificate-transparency/go/client"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

// LogDescription tells you how to connect to a log and verify its statements.
type LogDescription struct {
	Client   *ctClient.LogClient
	Verifier *ct.SignatureVerifier
}

type rawLogDescription struct {
	URI       string `json:"uri"`
	PublicKey string `json:"key"`
}

// UnmarshalJSON parses a simple JSON format for log descriptions.  Both the
// URI and the public key are expected to be strings.  The public key is a
// base64-encoded PKIX public key structure.
func (logDesc *LogDescription) UnmarshalJSON(data []byte) error {
	var rawLogDesc rawLogDescription
	err := json.Unmarshal(data, &rawLogDesc)
	if err != nil {
		return fmt.Errorf("Failed to unmarshal log description, %s", err)
	}
	if strings.HasPrefix(rawLogDesc.URI, "/") {
		rawLogDesc.URI = rawLogDesc.URI[0 : len(rawLogDesc.URI)-2]
	}
	logDesc.Client = ctClient.New(rawLogDesc.URI)

	// Load Key
	pkBytes, err := base64.StdEncoding.DecodeString(rawLogDesc.PublicKey)
	if err != nil {
		return fmt.Errorf("Failed to decode base64 log public key")
	}
	pk, err := x509.ParsePKIXPublicKey(pkBytes)
	if err != nil {
		return fmt.Errorf("Failed to parse log public key")
	}
	ecdsaKey, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("Failed to unmarshal log description for %s, unsupported public key type", rawLogDesc.URI)
	}

	logDesc.Verifier, err = ct.NewSignatureVerifier(ecdsaKey)
	return err
}

// CTConfig defines the JSON configuration file schema
type CTConfig struct {
	Logs                       []LogDescription `json:"logs"`
	SubmissionRetries          int              `json:"submissionRetries"`
	SubmissionBackoffString    string           `json:"submissionBackoff"`
	IntermediateBundleFilename string           `json:"intermediateBundleFilename"`
}

type ctSubmissionRequest struct {
	Chain []string `json:"chain"`
}

// PublisherImpl defines a Publisher
type PublisherImpl struct {
	log               *blog.AuditLogger
	client            *http.Client
	submissionBackoff time.Duration
	submissionRetries int
	issuerBundle      []ct.ASN1Cert
	ctLogs            []LogDescription

	SA core.StorageAuthority
}

// NewPublisherImpl creates a Publisher that will submit certificates
// to any CT logs configured in CTConfig
func NewPublisherImpl(ctConfig CTConfig) (pub PublisherImpl, err error) {
	logger := blog.GetAuditLogger()
	logger.Notice("Publisher Authority Starting")

	if ctConfig.IntermediateBundleFilename == "" {
		err = fmt.Errorf("No CT submission bundle provided")
		return
	}
	bundle, err := core.LoadCertBundle(ctConfig.IntermediateBundleFilename)
	if err != nil {
		return
	}
	for _, cert := range bundle {
		pub.issuerBundle = append(pub.issuerBundle, ct.ASN1Cert(cert.Raw))
	}

	pub.log = logger
	pub.ctLogs = ctConfig.Logs

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
		sct, err := ctLog.Client.AddChain(chain)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			pub.log.Audit(fmt.Sprintf("Failed to submit certificate to CT log: %s", err))
			continue
		}

		err = ctLog.Verifier.VerifySCTSignature(*sct, ct.LogEntry{
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

		err = pub.SA.AddSCTReceipt(sct, core.SerialToString(cert.SerialNumber))
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			pub.log.Audit(fmt.Sprintf("Failed to store SCT receipt in database: %s", err))
			continue
		}
	}

	return nil
}
