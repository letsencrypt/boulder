package va

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/protobuf/proto"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	berrors "github.com/letsencrypt/boulder/errors"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/identifier"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/probs"
	vapb "github.com/letsencrypt/boulder/va/proto"
)

const (
	PrimaryPerspective = "Primary"
	allPerspectives    = "all"

	opDCVAndCAA = "dcv+caa"
	opDCV       = "dcv"
	opCAA       = "caa"

	pass = "pass"
	fail = "fail"
)

var (
	// badTLSHeader contains the string 'HTTP /' which is returned when
	// we try to talk TLS to a server that only talks HTTP
	badTLSHeader = []byte{0x48, 0x54, 0x54, 0x50, 0x2f}
	// h2SettingsFrameErrRegex is a regex against a net/http error indicating
	// a malformed HTTP response that matches the initial SETTINGS frame of an
	// HTTP/2 connection. This happens when a server configures HTTP/2 on port
	// :80, failing HTTP-01 challenges.
	//
	// The regex first matches the error string prefix and then matches the raw
	// bytes of an arbitrarily sized HTTP/2 SETTINGS frame:
	//   0x00 0x00 0x?? 0x04 0x00 0x00 0x00 0x00
	//
	// The third byte is variable and indicates the frame size. Typically
	// this will be 0x12.
	// The 0x04 in the fourth byte indicates that the frame is SETTINGS type.
	//
	// See:
	//   * https://tools.ietf.org/html/rfc7540#section-4.1
	//   * https://tools.ietf.org/html/rfc7540#section-6.5
	//
	// NOTE(@cpu): Using a regex is a hack but unfortunately for this case
	// http.Client.Do() will return a url.Error err that wraps
	// a errors.ErrorString instance. There isn't much else to do with one of
	// those except match the encoded byte string with a regex. :-X
	//
	// NOTE(@cpu): The first component of this regex is optional to avoid an
	// integration test flake. In some (fairly rare) conditions the malformed
	// response error will be returned simply as a http.badStringError without
	// the broken transport prefix. Most of the time the error is returned with
	// a transport connection error prefix.
	h2SettingsFrameErrRegex = regexp.MustCompile(`(?:net\/http\: HTTP\/1\.x transport connection broken: )?malformed HTTP response \"\\x00\\x00\\x[a-f0-9]{2}\\x04\\x00\\x00\\x00\\x00\\x00.*"`)
)

// RemoteClients wraps the vapb.VAClient and vapb.CAAClient interfaces to aid in
// mocking remote VAs for testing.
type RemoteClients struct {
	vapb.VAClient
	vapb.CAAClient
}

// RemoteVA embeds RemoteClients and adds a field containing the address of the
// remote gRPC server since the underlying gRPC client doesn't provide a way to
// extract this metadata which is useful for debugging gRPC connection issues.
type RemoteVA struct {
	RemoteClients
	Address     string
	Perspective string
	RIR         string
}

type vaMetrics struct {
	// validationLatency is a histogram of the latency to perform validations
	// from the primary and remote VA perspectives. It's labelled by:
	//   - operation: VA.DoDCV or VA.DoCAA as [dcv|caa|dcv+caa]
	//   - perspective: ValidationAuthorityImpl.perspective
	//   - challenge_type: core.Challenge.Type
	//   - problem_type: probs.ProblemType
	//   - result: the result of the validation as [pass|fail]
	validationLatency                 *prometheus.HistogramVec
	prospectiveRemoteCAACheckFailures prometheus.Counter
	tlsALPNOIDCounter                 *prometheus.CounterVec
	http01Fallbacks                   prometheus.Counter
	http01Redirects                   prometheus.Counter
	caaCounter                        *prometheus.CounterVec
	ipv4FallbackCounter               prometheus.Counter
}

func initMetrics(stats prometheus.Registerer) *vaMetrics {
	validationLatency := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "validation_latency",
			Help:    "Histogram of the latency to perform validations from the primary and remote VA perspectives",
			Buckets: metrics.InternetFacingBuckets,
		},
		[]string{"operation", "perspective", "challenge_type", "problem_type", "result"},
	)
	stats.MustRegister(validationLatency)
	prospectiveRemoteCAACheckFailures := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "prospective_remote_caa_check_failures",
			Help: "Number of CAA rechecks that would have failed due to remote VAs returning failure if consesus were enforced",
		})
	stats.MustRegister(prospectiveRemoteCAACheckFailures)
	tlsALPNOIDCounter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tls_alpn_oid_usage",
			Help: "Number of TLS ALPN validations using either of the two OIDs",
		},
		[]string{"oid"},
	)
	stats.MustRegister(tlsALPNOIDCounter)
	http01Fallbacks := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "http01_fallbacks",
			Help: "Number of IPv6 to IPv4 HTTP-01 fallback requests made",
		})
	stats.MustRegister(http01Fallbacks)
	http01Redirects := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "http01_redirects",
			Help: "Number of HTTP-01 redirects followed",
		})
	stats.MustRegister(http01Redirects)
	caaCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "caa_sets_processed",
		Help: "A counter of CAA sets processed labelled by result",
	}, []string{"result"})
	stats.MustRegister(caaCounter)
	ipv4FallbackCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "tls_alpn_ipv4_fallback",
		Help: "A counter of IPv4 fallbacks during TLS ALPN validation",
	})
	stats.MustRegister(ipv4FallbackCounter)

	return &vaMetrics{
		validationLatency:                 validationLatency,
		prospectiveRemoteCAACheckFailures: prospectiveRemoteCAACheckFailures,
		tlsALPNOIDCounter:                 tlsALPNOIDCounter,
		http01Fallbacks:                   http01Fallbacks,
		http01Redirects:                   http01Redirects,
		caaCounter:                        caaCounter,
		ipv4FallbackCounter:               ipv4FallbackCounter,
	}
}

// PortConfig specifies what ports the VA should call to on the remote
// host when performing its checks.
type portConfig struct {
	HTTPPort  int
	HTTPSPort int
	TLSPort   int
}

// newDefaultPortConfig is a constructor which returns a portConfig with default
// settings.
//
// CABF BRs section 1.6.1: Authorized Ports: One of the following ports: 80
// (http), 443 (https), 25 (smtp), 22 (ssh).
//
// RFC 8555 section 8.3: Dereference the URL using an HTTP GET request. This
// request MUST be sent to TCP port 80 on the HTTP server.
//
// RFC 8737 section 3: The ACME server initiates a TLS connection to the chosen
// IP address. This connection MUST use TCP port 443.
func newDefaultPortConfig() *portConfig {
	return &portConfig{
		HTTPPort:  80,
		HTTPSPort: 443,
		TLSPort:   443,
	}
}

// ValidationAuthorityImpl represents a VA
type ValidationAuthorityImpl struct {
	vapb.UnsafeVAServer
	vapb.UnsafeCAAServer
	log                blog.Logger
	dnsClient          bdns.Client
	issuerDomain       string
	httpPort           int
	httpsPort          int
	tlsPort            int
	userAgent          string
	clk                clock.Clock
	remoteVAs          []RemoteVA
	maxRemoteFailures  int
	accountURIPrefixes []string
	singleDialTimeout  time.Duration
	perspective        string
	rir                string

	metrics *vaMetrics
}

var _ vapb.VAServer = (*ValidationAuthorityImpl)(nil)
var _ vapb.CAAServer = (*ValidationAuthorityImpl)(nil)

// NewValidationAuthorityImpl constructs a new VA
func NewValidationAuthorityImpl(
	resolver bdns.Client,
	remoteVAs []RemoteVA,
	userAgent string,
	issuerDomain string,
	stats prometheus.Registerer,
	clk clock.Clock,
	logger blog.Logger,
	accountURIPrefixes []string,
	perspective string,
	rir string,
) (*ValidationAuthorityImpl, error) {

	if len(accountURIPrefixes) == 0 {
		return nil, errors.New("no account URI prefixes configured")
	}

	for i, va1 := range remoteVAs {
		for j, va2 := range remoteVAs {
			// TODO(#7615): Remove the != "" check once perspective is required.
			if i != j && va1.Perspective == va2.Perspective && va1.Perspective != "" {
				return nil, fmt.Errorf("duplicate remote VA perspective %q", va1.Perspective)
			}
		}
	}

	pc := newDefaultPortConfig()

	va := &ValidationAuthorityImpl{
		log:                logger,
		dnsClient:          resolver,
		issuerDomain:       issuerDomain,
		httpPort:           pc.HTTPPort,
		httpsPort:          pc.HTTPSPort,
		tlsPort:            pc.TLSPort,
		userAgent:          userAgent,
		clk:                clk,
		metrics:            initMetrics(stats),
		remoteVAs:          remoteVAs,
		maxRemoteFailures:  maxAllowedFailures(len(remoteVAs)),
		accountURIPrefixes: accountURIPrefixes,
		// singleDialTimeout specifies how long an individual `DialContext` operation may take
		// before timing out. This timeout ignores the base RPC timeout and is strictly
		// used for the DialContext operations that take place during an
		// HTTP-01 challenge validation.
		singleDialTimeout: 10 * time.Second,
		perspective:       perspective,
		rir:               rir,
	}

	return va, nil
}

// maxAllowedFailures returns the maximum number of allowed failures
// for a given number of remote perspectives, according to the "Quorum
// Requirements" table in BRs Section 3.2.2.9, as follows:
//
//	| # of Distinct Remote Network Perspectives Used | # of Allowed non-Corroborations |
//	| --- | --- |
//	| 2-5 |  1  |
//	| 6+  |  2  |
func maxAllowedFailures(perspectiveCount int) int {
	if perspectiveCount < 2 {
		return 0
	}
	if perspectiveCount < 6 {
		return 1
	}
	return 2
}

// verificationRequestEvent is logged once for each validation attempt. Its
// fields are exported for logging purposes.
type verificationRequestEvent struct {
	AuthzID       string
	Requester     int64
	Identifier    string
	Challenge     core.Challenge
	Error         string `json:",omitempty"`
	InternalError string `json:",omitempty"`
	Latency       float64
}

// ipError is an error type used to pass though the IP address of the remote
// host when an error occurs during HTTP-01 and TLS-ALPN domain validation.
type ipError struct {
	ip  net.IP
	err error
}

// newIPError wraps an error and the IP of the remote host in an ipError so we
// can display the IP in the problem details returned to the client.
func newIPError(ip net.IP, err error) error {
	return ipError{ip: ip, err: err}
}

// Unwrap returns the underlying error.
func (i ipError) Unwrap() error {
	return i.err
}

// Error returns a string representation of the error.
func (i ipError) Error() string {
	return fmt.Sprintf("%s: %s", i.ip, i.err)
}

// detailedError returns a ProblemDetails corresponding to an error
// that occurred during HTTP-01 or TLS-ALPN domain validation. Specifically it
// tries to unwrap known Go error types and present something a little more
// meaningful. It additionally handles `berrors.ConnectionFailure` errors by
// passing through the detailed message.
func detailedError(err error) *probs.ProblemDetails {
	var ipErr ipError
	if errors.As(err, &ipErr) {
		detailedErr := detailedError(ipErr.err)
		if ipErr.ip == nil {
			// This should never happen.
			return detailedErr
		}
		// Prefix the error message with the IP address of the remote host.
		detailedErr.Detail = fmt.Sprintf("%s: %s", ipErr.ip, detailedErr.Detail)
		return detailedErr
	}
	// net/http wraps net.OpError in a url.Error. Unwrap them.
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		prob := detailedError(urlErr.Err)
		prob.Detail = fmt.Sprintf("Fetching %s: %s", urlErr.URL, prob.Detail)
		return prob
	}

	var tlsErr tls.RecordHeaderError
	if errors.As(err, &tlsErr) && bytes.Equal(tlsErr.RecordHeader[:], badTLSHeader) {
		return probs.Malformed("Server only speaks HTTP, not TLS")
	}

	var netOpErr *net.OpError
	if errors.As(err, &netOpErr) {
		if fmt.Sprintf("%T", netOpErr.Err) == "tls.alert" {
			// All the tls.alert error strings are reasonable to hand back to a
			// user. Confirmed against Go 1.8.
			return probs.TLS(netOpErr.Error())
		} else if netOpErr.Timeout() && netOpErr.Op == "dial" {
			return probs.Connection("Timeout during connect (likely firewall problem)")
		} else if netOpErr.Timeout() {
			return probs.Connection(fmt.Sprintf("Timeout during %s (your server may be slow or overloaded)", netOpErr.Op))
		}
	}
	var syscallErr *os.SyscallError
	if errors.As(err, &syscallErr) {
		switch syscallErr.Err {
		case syscall.ECONNREFUSED:
			return probs.Connection("Connection refused")
		case syscall.ENETUNREACH:
			return probs.Connection("Network unreachable")
		case syscall.ECONNRESET:
			return probs.Connection("Connection reset by peer")
		}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return probs.Connection("Timeout after connect (your server may be slow or overloaded)")
	}
	if errors.Is(err, berrors.ConnectionFailure) {
		return probs.Connection(err.Error())
	}
	if errors.Is(err, berrors.Unauthorized) {
		return probs.Unauthorized(err.Error())
	}
	if errors.Is(err, berrors.DNS) {
		return probs.DNS(err.Error())
	}
	if errors.Is(err, berrors.Malformed) {
		return probs.Malformed(err.Error())
	}
	if errors.Is(err, berrors.CAA) {
		return probs.CAA(err.Error())
	}

	if h2SettingsFrameErrRegex.MatchString(err.Error()) {
		return probs.Connection("Server is speaking HTTP/2 over HTTP")
	}
	return probs.Connection("Error getting validation data")
}

// isPrimaryVA returns true if the VA is the primary validation perspective.
func (va *ValidationAuthorityImpl) isPrimaryVA() bool {
	return va.perspective == PrimaryPerspective
}

// validateChallenge simply passes through to the appropriate validation method
// depending on the challenge type.
func (va *ValidationAuthorityImpl) validateChallenge(
	ctx context.Context,
	ident identifier.ACMEIdentifier,
	kind core.AcmeChallenge,
	token string,
	keyAuthorization string,
) ([]core.ValidationRecord, error) {
	// Strip a (potential) leading wildcard token from the identifier.
	ident.Value = strings.TrimPrefix(ident.Value, "*.")

	switch kind {
	case core.ChallengeTypeHTTP01:
		return va.validateHTTP01(ctx, ident, token, keyAuthorization)
	case core.ChallengeTypeDNS01:
		return va.validateDNS01(ctx, ident, keyAuthorization)
	case core.ChallengeTypeTLSALPN01:
		return va.validateTLSALPN01(ctx, ident, keyAuthorization)
	}
	return nil, berrors.MalformedError("invalid challenge type %s", kind)
}

// observeLatency records entries in the validationLatency histogram of the
// latency to perform validations from the primary and remote VA perspectives.
// The labels are:
//   - operation: VA.DoDCV or VA.DoCAA as [dcv|caa]
//   - perspective: [ValidationAuthorityImpl.perspective|all]
//   - challenge_type: core.Challenge.Type
//   - problem_type: probs.ProblemType
//   - result: the result of the validation as [pass|fail]
func (va *ValidationAuthorityImpl) observeLatency(op, perspective, challType, probType, result string, latency time.Duration) {
	labels := prometheus.Labels{
		"operation":      op,
		"perspective":    perspective,
		"challenge_type": challType,
		"problem_type":   probType,
		"result":         result,
	}
	va.metrics.validationLatency.With(labels).Observe(latency.Seconds())
}

// remoteOperation is a func type that encapsulates the operation and request
// passed to va.performRemoteOperation. The operation must be a method on
// vapb.VAClient or vapb.CAAClient, and the request must be the corresponding
// proto.Message passed to that method.
type remoteOperation = func(context.Context, RemoteVA, proto.Message) (remoteResult, error)

// remoteResult is an interface that must be implemented by the results of a
// remoteOperation, such as *vapb.ValidationResult and *vapb.IsCAAValidResponse.
// It provides methods to access problem details, the associated perspective,
// and the RIR.
type remoteResult interface {
	proto.Message
	GetProblem() *corepb.ProblemDetails
	GetPerspective() string
	GetRir() string
}

var _ remoteResult = (*vapb.ValidationResult)(nil)
var _ remoteResult = (*vapb.IsCAAValidResponse)(nil)

// performRemoteOperation concurrently calls the provided operation with `req` and a
// RemoteVA once for each configured RemoteVA. It cancels remaining operations and returns
// early if either the required number of successful results is obtained or the number of
// failures exceeds va.maxRemoteFailures.
//
// Internal logic errors are logged. If the number of operation failures exceeds
// va.maxRemoteFailures, the first encountered problem is returned as a
// *probs.ProblemDetails.
func (va *ValidationAuthorityImpl) performRemoteOperation(ctx context.Context, op remoteOperation, req proto.Message) *probs.ProblemDetails {
	remoteVACount := len(va.remoteVAs)
	if remoteVACount == 0 {
		return nil
	}
	isCAAValidReq, isCAACheck := req.(*vapb.IsCAAValidRequest)

	type response struct {
		addr        string
		perspective string
		rir         string
		result      remoteResult
		err         error
	}

	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	responses := make(chan *response, remoteVACount)
	for _, i := range rand.Perm(remoteVACount) {
		go func(rva RemoteVA) {
			res, err := op(subCtx, rva, req)
			if err != nil {
				responses <- &response{rva.Address, rva.Perspective, rva.RIR, res, err}
				return
			}
			// TODO(#7615): Remove the != "" checks once perspective and rir are required.
			if (rva.Perspective != "" && res.GetPerspective() != "" && res.GetPerspective() != rva.Perspective) ||
				(rva.RIR != "" && res.GetRir() != "" && res.GetRir() != rva.RIR) {
				err = fmt.Errorf(
					"Expected perspective %q (%q) but got reply from %q (%q) - misconfiguration likely", rva.Perspective, rva.RIR, res.GetPerspective(), res.GetRir(),
				)
				responses <- &response{rva.Address, rva.Perspective, rva.RIR, res, err}
				return
			}
			responses <- &response{rva.Address, rva.Perspective, rva.RIR, res, err}
		}(va.remoteVAs[i])
	}

	required := remoteVACount - va.maxRemoteFailures
	var passed []string
	var failed []string
	var firstProb *probs.ProblemDetails

	for resp := range responses {
		var currProb *probs.ProblemDetails

		if resp.err != nil {
			// Failed to communicate with the remote VA.
			failed = append(failed, resp.perspective)

			if core.IsCanceled(resp.err) {
				currProb = probs.ServerInternal("Secondary validation RPC canceled")
			} else {
				va.log.Errf("Operation on remote VA (%s) failed: %s", resp.addr, resp.err)
				currProb = probs.ServerInternal("Secondary validation RPC failed")
			}
		} else if resp.result.GetProblem() != nil {
			// The remote VA returned a problem.
			failed = append(failed, resp.perspective)

			var err error
			currProb, err = bgrpc.PBToProblemDetails(resp.result.GetProblem())
			if err != nil {
				va.log.Errf("Operation on Remote VA (%s) returned malformed problem: %s", resp.addr, err)
				currProb = probs.ServerInternal("Secondary validation RPC returned malformed result")
			}
			if isCAACheck {
				// We're checking CAA, log the problem.
				va.log.Errf("Operation on Remote VA (%s) returned a problem: %s", resp.addr, currProb)
			}
		} else {
			// The remote VA returned a successful result.
			passed = append(passed, resp.perspective)
		}

		if firstProb == nil && currProb != nil {
			// A problem was encountered for the first time.
			firstProb = currProb
		}

		// To respond faster, if we get enough successes or too many failures, we cancel remaining RPCs.
		// Finish the loop to collect remaining responses into `failed` so we can rely on having a response
		// for every request we made.
		if len(passed) >= required {
			cancel()
		}
		if len(failed) > va.maxRemoteFailures {
			cancel()
		}

		// Once all the VAs have returned a result, break the loop.
		if len(passed)+len(failed) >= remoteVACount {
			break
		}
	}

	if isCAACheck {
		// We're checking CAA, log the results.
		va.logRemoteResults(isCAAValidReq, len(passed), len(failed))
	}

	if len(passed) >= required {
		return nil
	} else if len(failed) > va.maxRemoteFailures {
		firstProb.Detail = fmt.Sprintf("During secondary validation: %s", firstProb.Detail)
		return firstProb
	} else {
		// This condition should not occur - it indicates the passed/failed counts
		// neither met the required threshold nor the maxRemoteFailures threshold.
		return probs.ServerInternal("Too few remote RPC results")
	}
}

// logRemoteResults is called by performRemoteOperation when the request passed
// is *vapb.IsCAAValidRequest.
func (va *ValidationAuthorityImpl) logRemoteResults(req *vapb.IsCAAValidRequest, passed int, failed int) {
	if failed == 0 {
		// There's no point logging a differential line if everything succeeded.
		return
	}

	logOb := struct {
		Domain          string
		AccountID       int64
		ChallengeType   string
		RemoteSuccesses int
		RemoteFailures  int
	}{
		Domain:          req.Domain,
		AccountID:       req.AccountURIID,
		ChallengeType:   req.ValidationMethod,
		RemoteSuccesses: passed,
		RemoteFailures:  failed,
	}

	logJSON, err := json.Marshal(logOb)
	if err != nil {
		// log a warning - a marshaling failure isn't expected given the data
		// isn't critical enough to break validation by returning an error the
		// caller.
		va.log.Warningf("Could not marshal log object in "+
			"logRemoteDifferential: %s", err)
		return
	}

	va.log.Infof("remoteVADifferentials JSON=%s", string(logJSON))
}

// performLocalValidation performs primary domain control validation and then
// checks CAA. If either step fails, it immediately returns a bare error so
// that our audit logging can include the underlying error.
func (va *ValidationAuthorityImpl) performLocalValidation(
	ctx context.Context,
	ident identifier.ACMEIdentifier,
	regid int64,
	kind core.AcmeChallenge,
	token string,
	keyAuthorization string,
) ([]core.ValidationRecord, error) {
	// Do primary domain control validation. Any kind of error returned by this
	// counts as a validation error, and will be converted into an appropriate
	// probs.ProblemDetails by the calling function.
	records, err := va.validateChallenge(ctx, ident, kind, token, keyAuthorization)
	if err != nil {
		return records, err
	}

	// Do primary CAA checks. Any kind of error returned by this counts as not
	// receiving permission to issue, and will be converted into an appropriate
	// probs.ProblemDetails by the calling function.
	err = va.checkCAA(ctx, ident, &caaParams{
		accountURIID:     regid,
		validationMethod: kind,
	})
	if err != nil {
		return records, err
	}

	return records, nil
}

// PerformValidation conducts a local Domain Control Validation (DCV) and CAA
// check for the specified challenge and dnsName. When invoked on the primary
// Validation Authority (VA) and the local validation succeeds, it also performs
// DCV and CAA checks using the configured remote VAs. Failed validations are
// indicated by a non-nil Problems in the returned ValidationResult.
// PerformValidation returns error only for internal logic errors (and the
// client may receive errors from gRPC in the event of a communication problem).
// ValidationResult always includes a list of ValidationRecords, even when it
// also contains Problems. This method does NOT implement Multi-Perspective
// Issuance Corroboration as defined in BRs Sections 3.2.2.9 and 5.4.1.
func (va *ValidationAuthorityImpl) PerformValidation(ctx context.Context, req *vapb.PerformValidationRequest) (*vapb.ValidationResult, error) {
	if core.IsAnyNilOrZero(req, req.DnsName, req.Challenge, req.Authz, req.ExpectedKeyAuthorization) {
		return nil, berrors.InternalServerError("Incomplete validation request")
	}

	chall, err := bgrpc.PBToChallenge(req.Challenge)
	if err != nil {
		return nil, errors.New("challenge failed to deserialize")
	}

	err = chall.CheckPending()
	if err != nil {
		return nil, berrors.MalformedError("challenge failed consistency check: %s", err)
	}

	// Set up variables and a deferred closure to report validation latency
	// metrics and log validation errors. Below here, do not use := to redeclare
	// `prob`, or this will fail.
	var prob *probs.ProblemDetails
	var localLatency time.Duration
	start := va.clk.Now()
	logEvent := verificationRequestEvent{
		AuthzID:    req.Authz.Id,
		Requester:  req.Authz.RegID,
		Identifier: req.DnsName,
		Challenge:  chall,
	}
	defer func() {
		probType := ""
		outcome := fail
		if prob != nil {
			probType = string(prob.Type)
			logEvent.Error = prob.Error()
			logEvent.Challenge.Error = prob
			logEvent.Challenge.Status = core.StatusInvalid
		} else {
			logEvent.Challenge.Status = core.StatusValid
			outcome = pass
		}
		// Observe local validation latency (primary|remote).
		va.observeLatency(opDCVAndCAA, va.perspective, string(chall.Type), probType, outcome, localLatency)
		if va.isPrimaryVA() {
			// Observe total validation latency (primary+remote).
			va.observeLatency(opDCVAndCAA, allPerspectives, string(chall.Type), probType, outcome, va.clk.Since(start))
		}

		// Log the total validation latency.
		logEvent.Latency = va.clk.Since(start).Round(time.Millisecond).Seconds()
		va.log.AuditObject("Validation result", logEvent)
	}()

	// Do local validation. Note that we process the result in a couple ways
	// *before* checking whether it returned an error. These few checks are
	// carefully written to ensure that they work whether the local validation
	// was successful or not, and cannot themselves fail.
	records, err := va.performLocalValidation(
		ctx,
		identifier.NewDNS(req.DnsName),
		req.Authz.RegID,
		chall.Type,
		chall.Token,
		req.ExpectedKeyAuthorization)

	// Stop the clock for local validation latency.
	localLatency = va.clk.Since(start)

	// Check for malformed ValidationRecords
	logEvent.Challenge.ValidationRecord = records
	if err == nil && !logEvent.Challenge.RecordsSane() {
		err = errors.New("records from local validation failed sanity check")
	}

	if err != nil {
		logEvent.InternalError = err.Error()
		prob = detailedError(err)
		return bgrpc.ValidationResultToPB(records, filterProblemDetails(prob), va.perspective, va.rir)
	}

	// Do remote validation. We do this after local validation is complete to
	// avoid wasting work when validation will fail anyway. This only returns a
	// singular problem, because the remote VAs have already audit-logged their
	// own validation records, and it's not helpful to present multiple large
	// errors to the end user.
	op := func(ctx context.Context, remoteva RemoteVA, req proto.Message) (remoteResult, error) {
		validationRequest, ok := req.(*vapb.PerformValidationRequest)
		if !ok {
			return nil, fmt.Errorf("got type %T, want *vapb.PerformValidationRequest", req)
		}
		return remoteva.PerformValidation(ctx, validationRequest)
	}
	prob = va.performRemoteOperation(ctx, op, req)
	return bgrpc.ValidationResultToPB(records, filterProblemDetails(prob), va.perspective, va.rir)
}
