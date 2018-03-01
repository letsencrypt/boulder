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

	ct "github.com/google/certificate-transparency-go"
	ctClient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/context"

	"github.com/letsencrypt/boulder/canceled"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	pubpb "github.com/letsencrypt/boulder/publisher/proto"
)

// Log contains the CT client and signature verifier for a particular CT log
type Log struct {
	logID    string
	uri      string
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
func (c *logCache) AddLog(uri, b64PK string, logger blog.Logger) (*Log, error) {
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
	log, err := NewLog(uri, b64PK, logger)
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

type logAdaptor struct {
	blog.Logger
}

func (la logAdaptor) Printf(s string, args ...interface{}) {
	la.Logger.Info(fmt.Sprintf(s, args...))
}

// NewLog returns an initialized Log struct
func NewLog(uri, b64PK string, logger blog.Logger) (*Log, error) {
	url, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	url.Path = strings.TrimSuffix(url.Path, "/")

	pemPK := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----",
		b64PK)
	opts := jsonclient.Options{
		Logger:    logAdaptor{logger},
		PublicKey: pemPK,
	}
	// We set the HTTP client timeout to about half of what we expect
	// the gRPC timeout to be set to. This allows us to retry the
	// request at least twice in the case where the server we are
	// talking to is simply hanging indefinitely.
	httpClient := &http.Client{Timeout: time.Minute*2 + time.Second*30}
	client, err := ctClient.New(url.String(), httpClient, opts)
	if err != nil {
		return nil, fmt.Errorf("making CT client: %s", err)
	}

	// TODO: Maybe this isn't necessary any more now that ctClient can check sigs?
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

	return &Log{
		logID:    b64PK,
		uri:      url.String(),
		client:   client,
		verifier: verifier,
	}, nil
}

type ctSubmissionRequest struct {
	Chain []string `json:"chain"`
}

type pubMetrics struct {
	submissionLatency *prometheus.HistogramVec
}

func initMetrics(stats metrics.Scope) *pubMetrics {
	submissionLatency := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ct_submission_time_seconds",
			Help:    "Time taken to submit a certificate to a CT log",
			Buckets: []float64{.1, .25, .5, 1, 2.5, 5, 7.5, 10, 15, 30, 45},
		},
		[]string{"log", "status"},
	)
	stats.MustRegister(submissionLatency)

	return &pubMetrics{
		submissionLatency: submissionLatency,
	}
}

// Impl defines a Publisher
type Impl struct {
	log          blog.Logger
	client       *http.Client
	issuerBundle []ct.ASN1Cert
	ctLogsCache  logCache
	// ctLogs is slightly redundant with the logCache, and should be removed. See
	// issue https://github.com/letsencrypt/boulder/issues/2357
	ctLogs  []*Log
	metrics *pubMetrics

	sa core.StorageAuthority
}

// New creates a Publisher that will submit certificates
// to any CT logs configured in CTConfig
func New(
	bundle []ct.ASN1Cert,
	logs []*Log,
	logger blog.Logger,
	stats metrics.Scope,
	sa core.StorageAuthority,
) *Impl {
	return &Impl{
		issuerBundle: bundle,
		ctLogsCache: logCache{
			logs: make(map[string]*Log),
		},
		ctLogs:  logs,
		log:     logger,
		sa:      sa,
		metrics: initMetrics(stats),
	}
}

// SubmitToSingleCT will submit the certificate represented by certDER to the CT
// log specified by log URL and public key (base64)
func (pub *Impl) SubmitToSingleCT(ctx context.Context, logURL, logPublicKey string, der []byte) error {
	// NOTE(@roland): historically we've always thrown any errors away when
	// using this method. In order to preserve this behaviour we just ignore
	// any returns and return nil.
	_, _ = pub.SubmitToSingleCTWithResult(ctx, &pubpb.Request{LogURL: &logURL, LogPublicKey: &logPublicKey, Der: der})
	return nil
}

// SubmitToSingleCTWithResult will submit the certificate represented by certDER to the CT
// log specified by log URL and public key (base64) and return the SCT to the caller
func (pub *Impl) SubmitToSingleCTWithResult(ctx context.Context, req *pubpb.Request) (*pubpb.Result, error) {
	cert, err := x509.ParseCertificate(req.Der)
	if err != nil {
		pub.log.AuditErr(fmt.Sprintf("Failed to parse certificate: %s", err))
		return nil, err
	}

	chain := append([]ct.ASN1Cert{ct.ASN1Cert{req.Der}}, pub.issuerBundle...)

	// Add a log URL/pubkey to the cache, if already present the
	// existing *Log will be returned, otherwise one will be constructed, added
	// and returned.
	ctLog, err := pub.ctLogsCache.AddLog(*req.LogURL, *req.LogPublicKey, pub.log)
	if err != nil {
		pub.log.AuditErr(fmt.Sprintf("Making Log: %s", err))
		return nil, err
	}

	sct, err := pub.singleLogSubmit(
		ctx,
		chain,
		core.SerialToString(cert.SerialNumber),
		ctLog)
	if err != nil {
		if !canceled.Is(err) {
			pub.log.AuditErr(
				fmt.Sprintf("Failed to submit certificate to CT log at %s: %s", ctLog.uri, err))
		}
		return nil, err
	}

	sctBytes, err := tls.Marshal(*sct)
	if err != nil {
		return nil, err
	}
	return &pubpb.Result{Sct: sctBytes}, nil
}

// SubmitToCT will submit the certificate represented by certDER to any CT
// logs configured in pub.CT.Logs.
func (pub *Impl) SubmitToCT(ctx context.Context, der []byte) error {
	wg := new(sync.WaitGroup)
	for _, ctLog := range pub.ctLogs {
		wg.Add(1)
		// Do each submission in a goroutine so a single slow log doesn't eat
		// all of the context and prevent submission to the rest of the logs
		go func(ctLog *Log) {
			defer wg.Done()
			// Nothing actually consumes the errors returned from SubmitToCT
			// so instead of using a channel to collect them we just throw
			// it away here.
			_ = pub.SubmitToSingleCT(ctx, ctLog.uri, ctLog.logID, der)
		}(ctLog)
	}
	wg.Wait()
	return nil
}

func (pub *Impl) singleLogSubmit(
	ctx context.Context,
	chain []ct.ASN1Cert,
	serial string,
	ctLog *Log) (*ct.SignedCertificateTimestamp, error) {

	start := time.Now()
	sct, err := ctLog.client.AddChain(ctx, chain)
	took := time.Since(start).Seconds()
	if err != nil {
		if canceled.Is(err) {
			pub.metrics.submissionLatency.With(prometheus.Labels{
				"log":    ctLog.uri,
				"status": "canceled",
			}).Observe(took)
		} else {
			pub.metrics.submissionLatency.With(prometheus.Labels{
				"log":    ctLog.uri,
				"status": "error",
			}).Observe(took)
		}
		return nil, err
	}
	pub.metrics.submissionLatency.With(prometheus.Labels{
		"log":    ctLog.uri,
		"status": "success",
	}).Observe(took)

	err = ctLog.verifier.VerifySCTSignature(*sct, ct.LogEntry{
		Leaf: ct.MerkleTreeLeaf{
			LeafType: ct.TimestampedEntryLeafType,
			TimestampedEntry: &ct.TimestampedEntry{
				X509Entry: &chain[0],
				EntryType: ct.X509LogEntryType,
			},
		},
	})
	if err != nil {
		return nil, err
	}

	err = pub.sa.AddSCTReceipt(ctx, sctToInternal(sct, serial))
	if err != nil {
		return nil, err
	}
	return sct, nil
}

func sctToInternal(sct *ct.SignedCertificateTimestamp, serial string) core.SignedCertificateTimestamp {
	return core.SignedCertificateTimestamp{
		CertificateSerial: serial,
		SCTVersion:        uint8(sct.SCTVersion),
		LogID:             base64.StdEncoding.EncodeToString(sct.LogID.KeyID[:]),
		Timestamp:         sct.Timestamp,
		Extensions:        sct.Extensions,
		Signature:         sct.Signature.Signature,
	}
}
