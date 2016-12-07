package publisher

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
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
	logID    string
	uri      string
	statName string
	client   *ctClient.LogClient
	verifier *ct.SignatureVerifier
}

// logCache contains a cache of *Log's that are constructed as required by
// `SubmitToSingleCT`
type logCache struct {
	sync.RWMutex
	logs map[string]*Log
}

// AddLog adds a *Log to the cache by constructing the statName, client and
// verifier for the given uri & base64 public key.
func (c *logCache) AddLog(uri, b64PK string) (*Log, error) {
	// Lock the mutex for reading to check the cache
	c.RLock()
	log, present := c.logs[b64PK]
	c.RUnlock()

	// If we have already added this log, give it back
	if present {
		return log, nil
	}

	// Lock the mutex for writing to add to the cache
	c.Lock()
	defer c.Unlock()

	// Construct a Log, add it to the cache, and return it to the caller
	log, err := NewLog(uri, b64PK)
	if err != nil {
		return nil, err
	}
	c.logs[b64PK] = log
	return log, nil
}

// Len returns the number of logs in the logCache
func (c *logCache) Len() int {
	c.RLock()
	defer c.RUnlock()
	return len(c.logs)
}

// NewLog returns an initialized Log struct
func NewLog(uri, b64PK string) (*Log, error) {
	url, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	url.Path = strings.TrimSuffix(url.Path, "/")
	client := ctClient.New(url.String(), nil)

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

	// Replace slashes with dots for statsd logging
	sanitizedPath := strings.TrimPrefix(url.Path, "/")
	sanitizedPath = strings.Replace(sanitizedPath, "/", ".", -1)

	return &Log{
		logID:    b64PK,
		uri:      uri,
		statName: fmt.Sprintf("%s.%s", url.Host, sanitizedPath),
		client:   client,
		verifier: verifier,
	}, nil
}

type ctSubmissionRequest struct {
	Chain []string `json:"chain"`
}

// Impl defines a Publisher
type Impl struct {
	log          blog.Logger
	stats        metrics.Scope
	client       *http.Client
	issuerBundle []ct.ASN1Cert
	ctLogsCache  logCache
	// ctLogs is slightly redundant with the logCache, and should be removed. See
	// issue https://github.com/letsencrypt/boulder/issues/2357
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
		ctLogsCache: logCache{
			logs: make(map[string]*Log),
		},
		ctLogs: logs,
		log:    logger,
		stats:  stats,
		sa:     sa,
	}
}

// SubmitToSingleCT will submit the certificate represented by certDER to the CT
// log specified by log URL and public key (base64)
func (pub *Impl) SubmitToSingleCT(
	ctx context.Context,
	logURL, logPublicKey string,
	der []byte) error {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		pub.log.AuditErr(fmt.Sprintf("Failed to parse certificate: %s", err))
		return err
	}

	localCtx, cancel := context.WithTimeout(ctx, pub.submissionTimeout)
	defer cancel()
	chain := append([]ct.ASN1Cert{der}, pub.issuerBundle...)

	// Add a log URL/pubkey to the cache, if already present the
	// existing *Log will be returned, otherwise one will be constructed, added
	// and returned.
	ctLog, err := pub.ctLogsCache.AddLog(logURL, logPublicKey)
	if err != nil {
		pub.log.AuditErr(fmt.Sprintf("Making Log: %s", err))
		return err
	}

	stats := pub.stats.NewScope(ctLog.statName)
	stats.Inc("Submits", 1)
	start := time.Now()
	err = pub.singleLogSubmit(
		localCtx,
		chain,
		core.SerialToString(cert.SerialNumber),
		ctLog)
	stats.TimingDuration("SubmitLatency", time.Now().Sub(start))
	if err != nil {
		pub.log.AuditErr(
			fmt.Sprintf("Failed to submit certificate to CT log at %s: %s", ctLog.uri, err))
		stats.Inc("Errors", 1)
	}

	return nil
}

// SubmitToCT will submit the certificate represented by certDER to any CT
// logs configured in pub.CT.Logs (AMQP RPC method).
func (pub *Impl) SubmitToCT(ctx context.Context, der []byte) error {
	for _, ctLog := range pub.ctLogs {
		err := pub.SubmitToSingleCT(ctx, ctLog.uri, ctLog.logID, der)
		if err != nil {
			return err
		}
	}
	return nil
}

func (pub *Impl) singleLogSubmit(
	ctx context.Context,
	chain []ct.ASN1Cert,
	serial string,
	ctLog *Log) error {

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
