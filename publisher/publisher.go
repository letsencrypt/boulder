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
	"github.com/letsencrypt/boulder/metrics"
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
		uri = uri[0 : len(uri)-2]
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
	stats             metrics.Scope
	client            *http.Client
	issuerBundle      []ct.ASN1Cert
	ctLogs            []*Log
	submissionTimeout time.Duration

	sa core.StorageAuthority
}

// New creates a Publisher that will submit certificates
// to any CT logs configured in CTConfig
func New(
	bundle []ct.ASN1Cert,
	logs []*Log,
	submissionTimeout time.Duration,
	logger blog.Logger,
	stats metrics.Scope,
	sa core.StorageAuthority,
) *Impl {
	if submissionTimeout == 0 {
		submissionTimeout = time.Hour * 12
	}
	return &Impl{
		submissionTimeout: submissionTimeout,
		issuerBundle:      bundle,
		ctLogs:            logs,
		log:               logger,
		stats:             stats,
		sa:                sa,
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
		pub.stats.Inc("Submits", 1)
		start := time.Now()
		err := pub.singleLogSubmit(localCtx, chain, core.SerialToString(cert.SerialNumber), ctLog)
		pub.stats.TimingDuration("SubmitLatency", time.Now().Sub(start))
		if err != nil {
			pub.log.AuditErr(fmt.Sprintf("Failed to submit certificate to CT log at %s: %s", ctLog.uri, err))
			pub.stats.Inc("Errors", 1)
		}
	}
	return nil
}

func (pub *Impl) singleLogSubmit(ctx context.Context, chain []ct.ASN1Cert, serial string, ctLog *Log) error {
	sct, err := ctLog.client.AddChainWithContext(ctx, chain)
	if err != nil {
		return err
	}

	err = ctLog.verifier.VerifySCTSignature(*sct, ct.LogEntry{
		Leaf: ct.MerkleTreeLeaf{
			LeafType: ct.TimestampedEntryLeafType,
			TimestampedEntry: ct.TimestampedEntry{
				X509Entry: chain[0],
				EntryType: ct.X509LogEntryType,
			},
		},
	})
	if err != nil {
		return err
	}

	internalSCT, err := sctToInternal(sct, serial)
	if err != nil {
		return err
	}

	err = pub.sa.AddSCTReceipt(ctx, internalSCT)
	if err != nil {
		return err
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
