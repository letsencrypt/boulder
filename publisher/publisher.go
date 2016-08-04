package publisher

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency/go"
	ctClient "github.com/google/certificate-transparency/go/client"
	"golang.org/x/net/context"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

// Log contains the CT client and signature verifier for a particular CT log
type Log struct {
	uri      string
	client   *ctClient.LogClient
	verifier *ct.SignatureVerifier
}

// NewLog returns an initialized Log struct
func NewLog(uri, b64PK string) (*Log, error) {
	if strings.HasSuffix(uri, "/") {
		uri = uri[0 : len(uri)-1]
	}
	client := ctClient.New(uri, nil)

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

	return &Log{uri, client, verifier}, nil
}

type ctSubmissionRequest struct {
	Chain []string `json:"chain"`
}

// Impl defines a Publisher
type Impl struct {
	log               blog.Logger
	client            *http.Client
	issuerBundle      []ct.ASN1Cert
	ctLogs            []*Log
	submissionTimeout time.Duration

	SA core.StorageAuthority
}

// New creates a Publisher that will submit certificates
// to any CT logs configured in CTConfig
func New(bundle []ct.ASN1Cert, logs []*Log, submissionTimeout time.Duration, logger blog.Logger) *Impl {
	if submissionTimeout == 0 {
		submissionTimeout = time.Hour * 12
	}
	return &Impl{
		submissionTimeout: submissionTimeout,
		issuerBundle:      bundle,
		ctLogs:            logs,
		log:               logger,
	}
}

// SubmitToCT will submit the certificate represented by certDER to any CT
// logs configured in pub.CT.Logs (AMQP RPC method).
func (pub *Impl) SubmitToCT(ctx context.Context, der []byte) error {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		pub.log.AuditErr(fmt.Sprintf("Failed to parse certificate: %s", err))
		return err
	}

	localCtx, cancel := context.WithTimeout(ctx, pub.submissionTimeout)
	defer cancel()
	chain := append([]ct.ASN1Cert{der}, pub.issuerBundle...)
	for _, ctLog := range pub.ctLogs {
		sct, err := ctLog.client.AddChainWithContext(localCtx, chain)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			pub.log.AuditErr(fmt.Sprintf("Failed to submit certificate to CT log at %s: %s", ctLog.uri, err))
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
			pub.log.AuditErr(fmt.Sprintf("Failed to verify SCT receipt: %s", err))
			continue
		}

		internalSCT, err := sctToInternal(sct, core.SerialToString(cert.SerialNumber))
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			pub.log.AuditErr(fmt.Sprintf("Failed to convert SCT receipt: %s", err))
			continue
		}

		err = pub.SA.AddSCTReceipt(localCtx, internalSCT)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			pub.log.AuditErr(fmt.Sprintf("Failed to store SCT receipt in database: %s", err))
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
