package publisher

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/certificate-transparency-go"
	ctClient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/tls"
	cttls "github.com/google/certificate-transparency-go/tls"
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

// LogURIs returns the URIs of all logs currently in the logCache
func (c *logCache) LogURIs() []string {
	c.RLock()
	defer c.RUnlock()
	var uris []string
	for _, l := range c.logs {
		uris = append(uris, l.uri)
	}
	return uris
}

type logAdaptor struct {
	blog.Logger
}

func (la logAdaptor) Printf(s string, args ...interface{}) {
	la.Logger.Infof(s, args...)
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
	probeLatency      *prometheus.HistogramVec
}

func initMetrics(stats metrics.Scope) *pubMetrics {
	submissionLatency := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ct_submission_time_seconds",
			Help:    "Time taken to submit a certificate to a CT log",
			Buckets: metrics.InternetFacingBuckets,
		},
		[]string{"log", "status"},
	)
	stats.MustRegister(submissionLatency)

	probeLatency := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ct_probe_time_seconds",
			Help:    "Time taken to probe a CT log",
			Buckets: metrics.InternetFacingBuckets,
		},
		[]string{"log", "status"},
	)
	stats.MustRegister(probeLatency)

	return &pubMetrics{
		submissionLatency: submissionLatency,
		probeLatency:      probeLatency,
	}
}

// Impl defines a Publisher
type Impl struct {
	log          blog.Logger
	issuerBundle []ct.ASN1Cert
	ctLogsCache  logCache
	metrics      *pubMetrics
}

// New creates a Publisher that will submit certificates
// to requested CT logs
func New(
	bundle []ct.ASN1Cert,
	logger blog.Logger,
	stats metrics.Scope,
) *Impl {
	return &Impl{
		issuerBundle: bundle,
		ctLogsCache: logCache{
			logs: make(map[string]*Log),
		},
		log:     logger,
		metrics: initMetrics(stats),
	}
}

// SubmitToSingleCTWithResult will submit the certificate represented by certDER to the CT
// log specified by log URL and public key (base64) and return the SCT to the caller
func (pub *Impl) SubmitToSingleCTWithResult(ctx context.Context, req *pubpb.Request) (*pubpb.Result, error) {
	cert, err := x509.ParseCertificate(req.Der)
	if err != nil {
		pub.log.AuditErrf("Failed to parse certificate: %s", err)
		return nil, err
	}

	chain := append([]ct.ASN1Cert{ct.ASN1Cert{Data: req.Der}}, pub.issuerBundle...)

	// Add a log URL/pubkey to the cache, if already present the
	// existing *Log will be returned, otherwise one will be constructed, added
	// and returned.
	ctLog, err := pub.ctLogsCache.AddLog(*req.LogURL, *req.LogPublicKey, pub.log)
	if err != nil {
		pub.log.AuditErrf("Making Log: %s", err)
		return nil, err
	}

	isPrecert := false
	if req.Precert != nil {
		isPrecert = *req.Precert
	}

	sct, err := pub.singleLogSubmit(
		ctx,
		chain,
		isPrecert,
		core.SerialToString(cert.SerialNumber),
		ctLog)
	if err != nil {
		if canceled.Is(err) {
			return nil, err
		}
		var body string
		if respErr, ok := err.(ctClient.RspError); ok && respErr.StatusCode < 500 {
			body = string(respErr.Body)
		}
		pub.log.AuditErrf("Failed to submit certificate to CT log at %s: %s Body=%q",
			ctLog.uri, err, body)
		return nil, err
	}

	sctBytes, err := tls.Marshal(*sct)
	if err != nil {
		return nil, err
	}
	return &pubpb.Result{Sct: sctBytes}, nil
}

func (pub *Impl) singleLogSubmit(
	ctx context.Context,
	chain []ct.ASN1Cert,
	isPrecert bool,
	serial string,
	ctLog *Log,
) (*ct.SignedCertificateTimestamp, error) {
	var submissionMethod func(context.Context, []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error)
	submissionMethod = ctLog.client.AddChain
	if isPrecert {
		submissionMethod = ctLog.client.AddPreChain
	}

	start := time.Now()
	sct, err := submissionMethod(ctx, chain)
	took := time.Since(start).Seconds()
	if err != nil {
		status := "error"
		if canceled.Is(err) {
			status = "canceled"
		}
		pub.metrics.submissionLatency.With(prometheus.Labels{
			"log":    ctLog.uri,
			"status": status,
		}).Observe(took)
		return nil, err
	}
	pub.metrics.submissionLatency.With(prometheus.Labels{
		"log":    ctLog.uri,
		"status": "success",
	}).Observe(took)

	// Generate log entry so we can verify the signature in the returned SCT
	eType := ct.X509LogEntryType
	if isPrecert {
		eType = ct.PrecertLogEntryType
	}
	// Note: The timestamp on the merkle tree leaf is not actually used in
	// the SCT signature validation so it is left as 0 here
	leaf, err := ct.MerkleTreeLeafFromRawChain(chain, eType, 0)
	if err != nil {
		return nil, err
	}
	err = ctLog.verifier.VerifySCTSignature(*sct, ct.LogEntry{Leaf: *leaf})
	if err != nil {
		return nil, err
	}
	timestamp := time.Unix(int64(sct.Timestamp)/1000, 0)
	if timestamp.Sub(time.Now()) > time.Minute {
		return nil, fmt.Errorf("SCT Timestamp was too far in the future (%s)", timestamp)
	}
	// For regular certificates, we could get an old SCT, but that shouldn't
	// happen for precertificates.
	if isPrecert && timestamp.Sub(time.Now()) < -10*time.Minute {
		return nil, fmt.Errorf("SCT Timestamp was too far in the past (%s)", timestamp)
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

// CreateTestingSignedSCT is used by both the publisher tests and ct-test-serv, which is
// why it is exported. It creates a signed SCT based on the provided chain.
func CreateTestingSignedSCT(req []string, k *ecdsa.PrivateKey, precert bool, timestamp time.Time) []byte {
	chain := make([]ct.ASN1Cert, len(req))
	for i, str := range req {
		b, err := base64.StdEncoding.DecodeString(str)
		if err != nil {
			panic("cannot decode chain")
		}
		chain[i] = ct.ASN1Cert{Data: b}
	}

	// Generate the internal leaf entry for the SCT
	etype := ct.X509LogEntryType
	if precert {
		etype = ct.PrecertLogEntryType
	}
	leaf, err := ct.MerkleTreeLeafFromRawChain(chain, etype, 0)
	if err != nil {
		panic(fmt.Sprintf("failed to create leaf: %s", err))
	}

	// Sign the SCT
	rawKey, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	logID := sha256.Sum256(rawKey)
	timestampMillis := uint64(timestamp.UnixNano()) / 1e6
	serialized, _ := ct.SerializeSCTSignatureInput(ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		LogID:      ct.LogID{KeyID: logID},
		Timestamp:  timestampMillis,
	}, ct.LogEntry{Leaf: *leaf})
	hashed := sha256.Sum256(serialized)
	var ecdsaSig struct {
		R, S *big.Int
	}
	ecdsaSig.R, ecdsaSig.S, _ = ecdsa.Sign(rand.Reader, k, hashed[:])
	sig, _ := asn1.Marshal(ecdsaSig)

	// The ct.SignedCertificateTimestamp object doesn't have the needed
	// `json` tags to properly marshal so we need to transform in into
	// a struct that does before we can send it off
	var jsonSCTObj struct {
		SCTVersion ct.Version `json:"sct_version"`
		ID         string     `json:"id"`
		Timestamp  uint64     `json:"timestamp"`
		Extensions string     `json:"extensions"`
		Signature  string     `json:"signature"`
	}
	jsonSCTObj.SCTVersion = ct.V1
	jsonSCTObj.ID = base64.StdEncoding.EncodeToString(logID[:])
	jsonSCTObj.Timestamp = timestampMillis
	ds := ct.DigitallySigned{
		Algorithm: cttls.SignatureAndHashAlgorithm{
			Hash:      cttls.SHA256,
			Signature: cttls.ECDSA,
		},
		Signature: sig,
	}
	jsonSCTObj.Signature, _ = ds.Base64String()

	jsonSCT, _ := json.Marshal(jsonSCTObj)
	return jsonSCT
}

// ProbeLogs sends a HTTP GET request to each of the logs in the
// publisher logCache and records the latency and status of the
// response.
func (pub *Impl) ProbeLogs() {
	wg := new(sync.WaitGroup)
	for _, log := range pub.ctLogsCache.LogURIs() {
		wg.Add(1)
		go func(uri string) {
			defer wg.Done()
			c := http.Client{
				Timeout: time.Minute*2 + time.Second*30,
			}
			url, err := url.Parse(uri)
			if err != nil {
				pub.log.Errf("failed to parse log URI: %s", err)
			}
			url.Path = ct.GetSTHPath
			s := time.Now()
			resp, err := c.Get(url.String())
			took := time.Since(s).Seconds()
			var status string
			if err == nil {
				defer func() { _ = resp.Body.Close() }()
				status = resp.Status
			} else {
				status = "error"
			}
			pub.metrics.probeLatency.With(prometheus.Labels{
				"log":    uri,
				"status": status,
			}).Observe(took)
		}(log)
	}
	wg.Wait()
}
