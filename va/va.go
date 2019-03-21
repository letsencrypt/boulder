package va

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/canceled"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/probs"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/context"
)

const (
	maxRedirect      = 10
	whitespaceCutset = "\n\r\t "
	// Payload should be ~87 bytes. Since it may be padded by whitespace which we previously
	// allowed accept up to 128 bytes before rejecting a response
	// (32 byte b64 encoded token + . + 32 byte b64 encoded key fingerprint)
	maxResponseSize = 128

	// ALPN protocol ID for TLS-ALPN-01 challenge
	// https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-01#section-5.2
	ACMETLS1Protocol = "acme-tls/1"
)

// NOTE: unfortunately another document claimed the OID we were using in draft-ietf-acme-tls-alpn-01
// for their own extension and IANA chose to assign it early. Because of this we had to increment
// the id-pe-acmeIdentifier OID. Since there are in the wild implementations that use the original
// OID we still need to support it until everyone is switched over to the new one.
// As defined in https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-01#section-5.1
// id-pe OID + 30 (acmeIdentifier) + 1 (v1)
var IdPeAcmeIdentifierV1Obsolete = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 30, 1}

// As defined in https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-04#section-5.1
// id-pe OID + 31 (acmeIdentifier)
var IdPeAcmeIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

// RemoteVA wraps the core.ValidationAuthority interface and adds a field containing the addresses
// of the remote gRPC server since the interface (and the underlying gRPC client) doesn't
// provide a way to extract this metadata which is useful for debugging gRPC connection issues.
type RemoteVA struct {
	core.ValidationAuthority
	Addresses string
}

type vaMetrics struct {
	validationTime                      *prometheus.HistogramVec
	remoteValidationTime                *prometheus.HistogramVec
	remoteValidationFailures            prometheus.Counter
	prospectiveRemoteValidationFailures prometheus.Counter
	tlsALPNOIDCounter                   *prometheus.CounterVec
	http01Fallbacks                     prometheus.Counter
	http01Redirects                     prometheus.Counter
}

func initMetrics(stats metrics.Scope) *vaMetrics {
	validationTime := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "validation_time",
			Help:    "Time taken to validate a challenge",
			Buckets: metrics.InternetFacingBuckets,
		},
		[]string{"type", "result", "problemType"})
	stats.MustRegister(validationTime)
	remoteValidationTime := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "remote_validation_time",
			Help:    "Time taken to remotely validate a challenge",
			Buckets: metrics.InternetFacingBuckets,
		},
		[]string{"type", "result"})
	stats.MustRegister(remoteValidationTime)
	remoteValidationFailures := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "remote_validation_failures",
			Help: "Number of validations failed due to remote VAs returning failure when consensus is enforced",
		})
	stats.MustRegister(remoteValidationFailures)
	prospectiveRemoteValidationFailures := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "prospective_remote_validation_failures",
			Help: "Number of validations that would have failed due to remote VAs returning failure if consesus were enforced",
		})
	stats.MustRegister(prospectiveRemoteValidationFailures)
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

	return &vaMetrics{
		validationTime:                      validationTime,
		remoteValidationTime:                remoteValidationTime,
		remoteValidationFailures:            remoteValidationFailures,
		prospectiveRemoteValidationFailures: prospectiveRemoteValidationFailures,
		tlsALPNOIDCounter:                   tlsALPNOIDCounter,
		http01Fallbacks:                     http01Fallbacks,
		http01Redirects:                     http01Redirects,
	}
}

// ValidationAuthorityImpl represents a VA
type ValidationAuthorityImpl struct {
	log                blog.Logger
	dnsClient          bdns.DNSClient
	issuerDomain       string
	httpPort           int
	httpsPort          int
	tlsPort            int
	userAgent          string
	stats              metrics.Scope
	clk                clock.Clock
	remoteVAs          []RemoteVA
	maxRemoteFailures  int
	accountURIPrefixes []string
	singleDialTimeout  time.Duration

	metrics *vaMetrics
}

// NewValidationAuthorityImpl constructs a new VA
func NewValidationAuthorityImpl(
	pc *cmd.PortConfig,
	resolver bdns.DNSClient,
	remoteVAs []RemoteVA,
	maxRemoteFailures int,
	userAgent string,
	issuerDomain string,
	stats metrics.Scope,
	clk clock.Clock,
	logger blog.Logger,
	accountURIPrefixes []string,
) (*ValidationAuthorityImpl, error) {
	if pc.HTTPPort == 0 {
		pc.HTTPPort = 80
	}
	if pc.HTTPSPort == 0 {
		pc.HTTPSPort = 443
	}
	if pc.TLSPort == 0 {
		pc.TLSPort = 443
	}

	if features.Enabled(features.CAAAccountURI) && len(accountURIPrefixes) == 0 {
		return nil, errors.New("no account URI prefixes configured")
	}

	return &ValidationAuthorityImpl{
		log:                logger,
		dnsClient:          resolver,
		issuerDomain:       issuerDomain,
		httpPort:           pc.HTTPPort,
		httpsPort:          pc.HTTPSPort,
		tlsPort:            pc.TLSPort,
		userAgent:          userAgent,
		stats:              stats,
		clk:                clk,
		metrics:            initMetrics(stats),
		remoteVAs:          remoteVAs,
		maxRemoteFailures:  maxRemoteFailures,
		accountURIPrefixes: accountURIPrefixes,
		// singleDialTimeout specifies how long an individual `DialContext` operation may take
		// before timing out. This timeout ignores the base RPC timeout and is strictly
		// used for the DialContext operations that take place during an
		// HTTP-01 challenge validation.
		singleDialTimeout: 10 * time.Second,
	}, nil
}

// Used for audit logging
type verificationRequestEvent struct {
	ID                string         `json:",omitempty"`
	Requester         int64          `json:",omitempty"`
	Hostname          string         `json:",omitempty"`
	Challenge         core.Challenge `json:",omitempty"`
	ValidationLatency float64
	Error             string `json:",omitempty"`
}

// getAddr will query for all A/AAAA records associated with hostname and return
// the preferred address, the first net.IP in the addrs slice, and all addresses
// resolved. This is the same choice made by the Go internal resolution library
// used by net/http.
func (va ValidationAuthorityImpl) getAddrs(ctx context.Context, hostname string) ([]net.IP, *probs.ProblemDetails) {
	addrs, err := va.dnsClient.LookupHost(ctx, hostname)
	if err != nil {
		problem := probs.DNS("%v", err)
		return nil, problem
	}

	if len(addrs) == 0 {
		return nil, probs.UnknownHost("No valid IP addresses found for %s", hostname)
	}
	va.log.Debugf("Resolved addresses for %s: %s", hostname, addrs)
	return addrs, nil
}

// availableAddresses takes a ValidationRecord and splits the AddressesResolved
// into a list of IPv4 and IPv6 addresses.
func availableAddresses(allAddrs []net.IP) (v4 []net.IP, v6 []net.IP) {
	for _, addr := range allAddrs {
		if addr.To4() != nil {
			v4 = append(v4, addr)
		} else {
			v6 = append(v6, addr)
		}
	}
	return
}

// certNames collects up all of a certificate's subject names (Subject CN and
// Subject Alternate Names) and reduces them to a unique, sorted set, typically for an
// error message
func certNames(cert *x509.Certificate) []string {
	var names []string
	if cert.Subject.CommonName != "" {
		names = append(names, cert.Subject.CommonName)
	}
	names = append(names, cert.DNSNames...)
	names = core.UniqueLowerNames(names)
	for i, n := range names {
		names[i] = replaceInvalidUTF8([]byte(n))
	}
	return names
}

func (va *ValidationAuthorityImpl) tryGetTLSCerts(ctx context.Context,
	identifier core.AcmeIdentifier, challenge core.Challenge,
	tlsConfig *tls.Config) ([]*x509.Certificate, *tls.ConnectionState, []core.ValidationRecord, *probs.ProblemDetails) {

	allAddrs, problem := va.getAddrs(ctx, identifier.Value)
	validationRecords := []core.ValidationRecord{
		{
			Hostname:          identifier.Value,
			AddressesResolved: allAddrs,
			Port:              strconv.Itoa(va.tlsPort),
		},
	}
	if problem != nil {
		return nil, nil, validationRecords, problem
	}
	thisRecord := &validationRecords[0]

	// Split the available addresses into v4 and v6 addresses
	v4, v6 := availableAddresses(allAddrs)
	addresses := append(v4, v6...)

	// This shouldn't happen, but be defensive about it anyway
	if len(addresses) < 1 {
		return nil, nil, validationRecords, probs.Malformed("no IP addresses found for %q", identifier.Value)
	}

	// If there is at least one IPv6 address then try it first
	if len(v6) > 0 {
		address := net.JoinHostPort(v6[0].String(), thisRecord.Port)
		thisRecord.AddressUsed = v6[0]

		certs, cs, err := va.getTLSCerts(ctx, address, identifier, challenge, tlsConfig)

		// If there is no error, return immediately
		if err == nil {
			return certs, cs, validationRecords, err
		}

		// Otherwise, we note that we tried an address and fall back to trying IPv4
		thisRecord.AddressesTried = append(thisRecord.AddressesTried, thisRecord.AddressUsed)
		va.stats.Inc("IPv4Fallback", 1)
	}

	// If there are no IPv4 addresses and we tried an IPv6 address return
	// an error - there's nothing left to try
	if len(v4) == 0 && len(thisRecord.AddressesTried) > 0 {
		return nil, nil, validationRecords, probs.Malformed("Unable to contact %q at %q, no IPv4 addresses to try as fallback",
			thisRecord.Hostname, thisRecord.AddressesTried[0])
	} else if len(v4) == 0 && len(thisRecord.AddressesTried) == 0 {
		// It shouldn't be possible that there are no IPv4 addresses and no previous
		// attempts at an IPv6 address connection but be defensive about it anyway
		return nil, nil, validationRecords, probs.Malformed("No IP addresses found for %q", thisRecord.Hostname)
	}

	// Otherwise if there are no IPv6 addresses, or there was an error
	// talking to the first IPv6 address, try the first IPv4 address
	thisRecord.AddressUsed = v4[0]
	certs, cs, err := va.getTLSCerts(ctx, net.JoinHostPort(v4[0].String(), thisRecord.Port),
		identifier, challenge, tlsConfig)
	return certs, cs, validationRecords, err
}

func (va *ValidationAuthorityImpl) getTLSCerts(
	ctx context.Context,
	hostPort string,
	identifier core.AcmeIdentifier,
	challenge core.Challenge,
	config *tls.Config,
) ([]*x509.Certificate, *tls.ConnectionState, *probs.ProblemDetails) {
	va.log.Info(fmt.Sprintf("%s [%s] Attempting to validate for %s %s", challenge.Type, identifier, hostPort, config.ServerName))
	// We expect a self-signed challenge certificate, do not verify it here.
	config.InsecureSkipVerify = true
	conn, err := va.tlsDial(ctx, hostPort, config)

	if err != nil {
		va.log.Infof("%s connection failure for %s. err=[%#v] errStr=[%s]", challenge.Type, identifier, err, err)
		return nil, nil, detailedError(err)
	}
	// close errors are not important here
	defer func() {
		_ = conn.Close()
	}()

	cs := conn.ConnectionState()
	certs := cs.PeerCertificates
	if len(certs) == 0 {
		va.log.Infof("%s challenge for %s resulted in no certificates", challenge.Type, identifier.Value)
		return nil, nil, probs.Unauthorized("No certs presented for %s challenge", challenge.Type)
	}
	for i, cert := range certs {
		va.log.AuditInfof("%s challenge for %s received certificate (%d of %d): cert=[%s]",
			challenge.Type, identifier.Value, i+1, len(certs), hex.EncodeToString(cert.Raw))
	}
	return certs, &cs, nil
}

// tlsDial does the equivalent of tls.Dial, but obeying a context. Once
// tls.DialContextWithDialer is available, switch to that.
func (va *ValidationAuthorityImpl) tlsDial(ctx context.Context, hostPort string, config *tls.Config) (*tls.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, va.singleDialTimeout)
	defer cancel()
	dialer := &net.Dialer{}
	netConn, err := dialer.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return nil, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		va.log.AuditErr("tlsDial was called without a deadline")
		return nil, fmt.Errorf("tlsDial was called without a deadline")
	}
	_ = netConn.SetDeadline(deadline)
	conn := tls.Client(netConn, config)
	err = conn.Handshake()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (va *ValidationAuthorityImpl) validateHTTP01(ctx context.Context, identifier core.AcmeIdentifier, challenge core.Challenge) ([]core.ValidationRecord, *probs.ProblemDetails) {
	if identifier.Type != core.IdentifierDNS {
		va.log.Infof("Got non-DNS identifier for HTTP validation: %s", identifier)
		return nil, probs.Malformed("Identifier type for HTTP validation was not DNS")
	}

	// Perform the fetch
	path := fmt.Sprintf(".well-known/acme-challenge/%s", challenge.Token)
	body, validationRecords, prob := va.fetchHTTP(ctx, identifier.Value, "/"+path)
	if prob != nil {
		return validationRecords, prob
	}

	payload := strings.TrimRight(string(body), whitespaceCutset)

	if payload != challenge.ProvidedKeyAuthorization {
		problem := probs.Unauthorized("The key authorization file from the server did not match this challenge [%v] != [%v]",
			challenge.ProvidedKeyAuthorization, payload)
		va.log.Infof("%s for %s", problem.Detail, identifier)
		return validationRecords, problem
	}

	return validationRecords, nil
}

func (va *ValidationAuthorityImpl) validateTLSALPN01(ctx context.Context, identifier core.AcmeIdentifier, challenge core.Challenge) ([]core.ValidationRecord, *probs.ProblemDetails) {
	if identifier.Type != "dns" {
		va.log.Info(fmt.Sprintf("Identifier type for TLS-ALPN-01 was not DNS: %s", identifier))
		return nil, probs.Malformed("Identifier type for TLS-ALPN-01 was not DNS")
	}

	certs, cs, validationRecords, problem := va.tryGetTLSCerts(ctx, identifier, challenge, &tls.Config{
		NextProtos: []string{ACMETLS1Protocol},
		ServerName: identifier.Value,
	})
	if problem != nil {
		return validationRecords, problem
	}

	if !cs.NegotiatedProtocolIsMutual || cs.NegotiatedProtocol != ACMETLS1Protocol {
		errText := fmt.Sprintf(
			"Cannot negotiate ALPN protocol %q for %s challenge",
			ACMETLS1Protocol,
			core.ChallengeTypeTLSALPN01,
		)
		return validationRecords, probs.Unauthorized(errText)
	}

	leafCert := certs[0]

	// Verify SNI - certificate returned must be issued only for the domain we are verifying.
	if len(leafCert.DNSNames) != 1 || !strings.EqualFold(leafCert.DNSNames[0], identifier.Value) {
		hostPort := net.JoinHostPort(validationRecords[0].AddressUsed.String(), validationRecords[0].Port)
		names := certNames(leafCert)
		errText := fmt.Sprintf(
			"Incorrect validation certificate for %s challenge. "+
				"Requested %s from %s. Received %d certificate(s), "+
				"first certificate had names %q",
			challenge.Type, identifier.Value, hostPort, len(certs), strings.Join(names, ", "))
		return validationRecords, probs.Unauthorized(errText)
	}

	// Verify key authorization in acmeValidation extension
	h := sha256.Sum256([]byte(challenge.ProvidedKeyAuthorization))
	for _, ext := range leafCert.Extensions {
		if IdPeAcmeIdentifier.Equal(ext.Id) || IdPeAcmeIdentifierV1Obsolete.Equal(ext.Id) {
			if IdPeAcmeIdentifier.Equal(ext.Id) {
				va.metrics.tlsALPNOIDCounter.WithLabelValues(IdPeAcmeIdentifier.String()).Inc()
			} else {
				va.metrics.tlsALPNOIDCounter.WithLabelValues(IdPeAcmeIdentifierV1Obsolete.String()).Inc()
			}
			if !ext.Critical {
				errText := fmt.Sprintf("Incorrect validation certificate for %s challenge. "+
					"acmeValidationV1 extension not critical.", core.ChallengeTypeTLSALPN01)
				return validationRecords, probs.Unauthorized(errText)
			}
			var extValue []byte
			rest, err := asn1.Unmarshal(ext.Value, &extValue)
			if err != nil || len(rest) > 0 {
				errText := fmt.Sprintf("Incorrect validation certificate for %s challenge. "+
					"Malformed acmeValidationV1 extension value.", core.ChallengeTypeTLSALPN01)
				return validationRecords, probs.Unauthorized(errText)
			}
			if subtle.ConstantTimeCompare(h[:], extValue) != 1 {
				errText := fmt.Sprintf("Incorrect validation certificate for %s challenge. "+
					"Invalid acmeValidationV1 extension value.", core.ChallengeTypeTLSALPN01)
				return validationRecords, probs.Unauthorized(errText)
			}
			return validationRecords, nil
		}
	}

	errText := fmt.Sprintf(
		"Incorrect validation certificate for %s challenge. "+
			"Missing acmeValidationV1 extension.",
		core.ChallengeTypeTLSALPN01)
	return validationRecords, probs.Unauthorized(errText)
}

// badTLSHeader contains the string 'HTTP /' which is returned when
// we try to talk TLS to a server that only talks HTTP
var badTLSHeader = []byte{0x48, 0x54, 0x54, 0x50, 0x2f}

// detailedError returns a ProblemDetails corresponding to an error
// that occurred during HTTP-01 or TLS-ALPN domain validation. Specifically it
// tries to unwrap known Go error types and present something a little more
// meaningful. It additionally handles `berrors.ConnectionFailure` errors by
// passing through the detailed message.
func detailedError(err error) *probs.ProblemDetails {
	// net/http wraps net.OpError in a url.Error. Unwrap them.
	if urlErr, ok := err.(*url.Error); ok {
		prob := detailedError(urlErr.Err)
		prob.Detail = fmt.Sprintf("Fetching %s: %s", urlErr.URL, prob.Detail)
		return prob
	}

	if tlsErr, ok := err.(tls.RecordHeaderError); ok && bytes.Compare(tlsErr.RecordHeader[:], badTLSHeader) == 0 {
		return probs.Malformed("Server only speaks HTTP, not TLS")
	}

	if netErr, ok := err.(*net.OpError); ok {
		if fmt.Sprintf("%T", netErr.Err) == "tls.alert" {
			// All the tls.alert error strings are reasonable to hand back to a
			// user. Confirmed against Go 1.8.
			return probs.TLSError(netErr.Error())
		} else if syscallErr, ok := netErr.Err.(*os.SyscallError); ok &&
			syscallErr.Err == syscall.ECONNREFUSED {
			return probs.ConnectionFailure("Connection refused")
		} else if syscallErr, ok := netErr.Err.(*os.SyscallError); ok &&
			syscallErr.Err == syscall.ENETUNREACH {
			return probs.ConnectionFailure("Network unreachable")
		} else if syscallErr, ok := netErr.Err.(*os.SyscallError); ok &&
			syscallErr.Err == syscall.ECONNRESET {
			return probs.ConnectionFailure("Connection reset by peer")
		} else if netErr.Timeout() && netErr.Op == "dial" {
			return probs.ConnectionFailure("Timeout during connect (likely firewall problem)")
		} else if netErr.Timeout() {
			return probs.ConnectionFailure("Timeout during %s (your server may be slow or overloaded)", netErr.Op)
		}
	}
	if err, ok := err.(net.Error); ok && err.Timeout() {
		return probs.ConnectionFailure("Timeout after connect (your server may be slow or overloaded)")
	}
	if berrors.Is(err, berrors.ConnectionFailure) {
		return probs.ConnectionFailure(err.Error())
	}
	if berrors.Is(err, berrors.Unauthorized) {
		return probs.Unauthorized(err.Error())
	}

	return probs.ConnectionFailure("Error getting validation data")
}

func (va *ValidationAuthorityImpl) validateDNS01(ctx context.Context, identifier core.AcmeIdentifier, challenge core.Challenge) ([]core.ValidationRecord, *probs.ProblemDetails) {
	if identifier.Type != core.IdentifierDNS {
		va.log.Infof("Identifier type for DNS challenge was not DNS: %s", identifier)
		return nil, probs.Malformed("Identifier type for DNS was not itself DNS")
	}

	// Compute the digest of the key authorization file
	h := sha256.New()
	h.Write([]byte(challenge.ProvidedKeyAuthorization))
	authorizedKeysDigest := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	// Look for the required record in the DNS
	challengeSubdomain := fmt.Sprintf("%s.%s", core.DNSPrefix, identifier.Value)
	txts, authorities, err := va.dnsClient.LookupTXT(ctx, challengeSubdomain)

	if err != nil {
		va.log.Infof("Failed to lookup TXT records for %s. err=[%#v] errStr=[%s]", identifier, err, err)
		return nil, probs.DNS(err.Error())
	}

	// If there weren't any TXT records return a distinct error message to allow
	// troubleshooters to differentiate between no TXT records and
	// invalid/incorrect TXT records.
	if len(txts) == 0 {
		return nil, probs.Unauthorized("No TXT record found at %s", challengeSubdomain)
	}

	for _, element := range txts {
		if subtle.ConstantTimeCompare([]byte(element), []byte(authorizedKeysDigest)) == 1 {
			// Successful challenge validation
			return []core.ValidationRecord{{
				Authorities: authorities,
				Hostname:    identifier.Value,
			}}, nil
		}
	}

	invalidRecord := txts[0]
	if len(invalidRecord) > 100 {
		invalidRecord = invalidRecord[0:100] + "..."
	}
	var andMore string
	if len(txts) > 1 {
		andMore = fmt.Sprintf(" (and %d more)", len(txts)-1)
	}
	return nil, probs.Unauthorized("Incorrect TXT record %q%s found at %s",
		replaceInvalidUTF8([]byte(invalidRecord)), andMore, challengeSubdomain)
}

// validate performs a challenge validation and, in parallel,
// checks CAA and GSB for the identifier. If any of those steps fails, it
// returns a ProblemDetails plus the validation records created during the
// validation attempt.
func (va *ValidationAuthorityImpl) validate(
	ctx context.Context,
	identifier core.AcmeIdentifier,
	challenge core.Challenge,
	authz core.Authorization,
) ([]core.ValidationRecord, *probs.ProblemDetails) {

	// If the identifier is a wildcard domain we need to validate the base
	// domain by removing the "*." wildcard prefix. We create a separate
	// `baseIdentifier` here before starting the `va.checkCAA` goroutine with the
	// `identifier` to avoid a data race.
	baseIdentifier := identifier
	if strings.HasPrefix(identifier.Value, "*.") {
		baseIdentifier.Value = strings.TrimPrefix(identifier.Value, "*.")
	}

	// va.checkCAA accepts wildcard identifiers and handles them appropriately so
	// we can dispatch `checkCAA` with the provided `identifier` instead of
	// `baseIdentifier`
	ch := make(chan *probs.ProblemDetails, 1)
	go func() {
		params := &caaParams{
			accountURIID:     &authz.RegistrationID,
			validationMethod: &challenge.Type,
		}
		ch <- va.checkCAA(ctx, identifier, params)
	}()

	// TODO(#1292): send into another goroutine
	validationRecords, err := va.validateChallenge(ctx, baseIdentifier, challenge)
	if err != nil {
		return validationRecords, err
	}

	for i := 0; i < cap(ch); i++ {
		if extraProblem := <-ch; extraProblem != nil {
			return validationRecords, extraProblem
		}
	}
	return validationRecords, nil
}

func (va *ValidationAuthorityImpl) validateChallenge(ctx context.Context, identifier core.AcmeIdentifier, challenge core.Challenge) ([]core.ValidationRecord, *probs.ProblemDetails) {
	if err := challenge.CheckConsistencyForValidation(); err != nil {
		return nil, probs.Malformed("Challenge failed consistency check: %s", err)
	}
	switch challenge.Type {
	case core.ChallengeTypeHTTP01:
		return va.validateHTTP01(ctx, identifier, challenge)
	case core.ChallengeTypeDNS01:
		return va.validateDNS01(ctx, identifier, challenge)
	case core.ChallengeTypeTLSALPN01:
		return va.validateTLSALPN01(ctx, identifier, challenge)
	}
	return nil, probs.Malformed("invalid challenge type %s", challenge.Type)
}

// performRemoteValidation calls `PerformValidation` for each of the configured
// remoteVAs in a random order. The provided `results` chan should have an equal
// size to the number of remote VAs. The validations will be peformed in
// separate go-routines. If the result `error` from a remote
// `PerformValidation` RPC is nil or a nil `ProblemDetails` instance it is
// written directly to the `results` chan. If the err is a cancelled error it is
// treated as a nil error. Otherwise the error/problem is written to the results
// channel as-is.
func (va *ValidationAuthorityImpl) performRemoteValidation(
	ctx context.Context,
	domain string,
	challenge core.Challenge,
	authz core.Authorization,
	results chan *probs.ProblemDetails) {
	for _, i := range rand.Perm(len(va.remoteVAs)) {
		remoteVA := va.remoteVAs[i]
		go func(rva RemoteVA, index int) {
			_, err := rva.PerformValidation(ctx, domain, challenge, authz)
			if err != nil {
				// returned error can be a nil *probs.ProblemDetails which breaks the
				// err != nil check so do a slightly more complicated unwrap check to
				// make sure we don't choke on that.
				// TODO(@cpu): Clean this up once boulder issue 2254[0] is resolved
				// [0] https://github.com/letsencrypt/boulder/issues/2254
				if p, ok := err.(*probs.ProblemDetails); ok && p != (*probs.ProblemDetails)(nil) {
					// If the non-nil err was a non-nil *probs.ProblemDetails then we can
					// log it at an info level. It's a normal non-success validation
					// result and the remote VA will have logged more detail.
					va.log.Infof("Remote VA %q.PerformValidation returned problem: %s", rva.Addresses, err)
				} else if ok && p == (*probs.ProblemDetails)(nil) {
					// If the non-nil err was a nil *probs.ProblemDetails then we don't need to do
					// anything. There isn't really an error here.
					err = nil
				} else if canceled.Is(err) {
					// If the non-nil err was a canceled error, ignore it. That's fine it
					// just means we cancelled the remote VA request before it was
					// finished because we didn't care about its result.
					err = nil
				} else if !ok {
					// Otherwise, the non-nil err was *not* a *probs.ProblemDetails and
					// was *not* a context cancelleded error and represents something that
					// will later be returned as a server internal error
					// without detail if the number of errors is >= va.maxRemoteFailures.
					// Log it at the error level so we can debug from logs.
					va.log.Errf("Remote VA %q.PerformValidation failed: %s", rva.Addresses, err)
				}
			}
			if err == nil {
				results <- nil
			} else if prob, ok := err.(*probs.ProblemDetails); ok {
				results <- prob
			} else {
				results <- probs.ServerInternal("Remote PerformValidation RPC failed")
			}
		}(remoteVA, i)
	}
}

// processRemoteResults evaluates a primary VA result, and a channel of remote
// VA problems to produce a single overall validation result based on configured
// feature flags. The overall result is calculated based on the VA's configured
// `maxRemoteFailures` value.
//
// If the `MultiVAFullResults` feature is enabled then `processRemoteResults`
// will expect to read a result from the `remoteErrors` channel for each VA and
// will not produce an overall result until all remote VAs have responded. In
// this case `logRemoteFailureDifferentials` will also be called to describe the
// differential between the primary and all of the remote VAs.
//
// If the `MultiVAFullResults` feature flag is not enabled then
// `processRemoteResults` will potentially return before all remote VAs have had
// a chance to respond. This happens if the success or failure threshold is met.
// This doesn't allow for logging the differential between the primary and
// remote VAs but is more performant.
func (va *ValidationAuthorityImpl) processRemoteResults(
	domain string,
	challengeType string,
	primaryResult *probs.ProblemDetails,
	remoteErrors chan *probs.ProblemDetails) *probs.ProblemDetails {

	state := "failure"
	start := va.clk.Now()

	defer func() {
		va.metrics.remoteValidationTime.With(prometheus.Labels{
			"type":   challengeType,
			"result": state,
		}).Observe(va.clk.Since(start).Seconds())
	}()

	required := len(va.remoteVAs) - va.maxRemoteFailures
	good := 0
	bad := 0

	var remoteProbs []*probs.ProblemDetails
	var firstProb *probs.ProblemDetails
	// Due to channel behavior this could block indefinitely and we rely on gRPC
	// honoring the context deadline used in client calls to prevent that from
	// happening.
	for prob := range remoteErrors {
		// Add the problem to the slice
		remoteProbs = append(remoteProbs, prob)
		if prob == nil {
			good++
		} else {
			bad++
		}

		// Store the first non-nil problem to return later (if `MultiVAFullResults`
		// is enabled).
		if firstProb == nil && prob != nil {
			firstProb = prob
		}

		// If MultiVAFullResults isn't enabled then return early whenever the
		// success or failure threshold is met.
		if !features.Enabled(features.MultiVAFullResults) {
			if good >= required {
				state = "success"
				return nil
			} else if bad > va.maxRemoteFailures {
				return prob
			}
		}

		// If we haven't returned early because of MultiVAFullResults being enabled
		// we need to break the loop once all of the VAs have returned a result.
		if len(remoteProbs) == len(va.remoteVAs) {
			break
		}
	}

	// If we are using `features.MultiVAFullResults` then we haven't returned
	// early and can now log the differential between what the primary VA saw and
	// what all of the remote VAs saw.
	va.logRemoteValidationDifferentials(domain, primaryResult, remoteProbs)

	// Based on the threshold of good/bad return nil or a problem.
	if good >= required {
		state = "success"
		return nil
	} else if bad > va.maxRemoteFailures {
		return firstProb
	}

	// This condition should not occur - it indicates the good/bad counts didn't
	// meet either the required threshold or the maxRemoteFailures threshold.
	return probs.ServerInternal("Too few remote PerformValidation RPC results")
}

// logRemoteValidationDifferentials is called by `processRemoteResults` when the
// `MultiVAFullResults` feature flag is enabled. It produces a JSON log line
// that contains the primary VA result and the results each remote VA returned.
func (va *ValidationAuthorityImpl) logRemoteValidationDifferentials(
	domain string,
	primaryResult *probs.ProblemDetails,
	remoteProbs []*probs.ProblemDetails) {

	var successes []*probs.ProblemDetails
	var failures []*probs.ProblemDetails

	allEqual := true
	for _, e := range remoteProbs {
		if e != primaryResult {
			allEqual = false
		}
		if e == nil {
			successes = append(successes, nil)
		} else {
			failures = append(failures, e)
		}
	}
	if allEqual {
		// There's no point logging a differential line if the primary VA and remote
		// VAs all agree.
		return
	}

	// If the primary result was OK and there were more failures than the allowed
	// threshold increment a stat that indicates this overall validation will have
	// failed if features.EnforceMultiVA is enabled.
	if primaryResult == nil && len(failures) > va.maxRemoteFailures {
		va.metrics.prospectiveRemoteValidationFailures.Inc()
	}

	logOb := struct {
		Domain          string
		PrimaryResult   *probs.ProblemDetails
		RemoteSuccesses int
		RemoteFailures  []*probs.ProblemDetails
	}{
		Domain:          domain,
		PrimaryResult:   primaryResult,
		RemoteSuccesses: len(successes),
		RemoteFailures:  failures,
	}

	logJSON, err := json.Marshal(logOb)
	if err != nil {
		// log a warning - a marshaling failure isn't expected given the data and
		// isn't critical enough to break validation for by returning an error to
		// the caller.
		va.log.Warningf("Could not marshal log object in "+
			"logRemoteValidationDifferentials: %s", err)
		return
	}

	va.log.Infof("remoteVADifferentials JSON=%s", string(logJSON))
}

// PerformValidation validates the given challenge. It always returns a list of
// validation records, even when it also returns an error.
func (va *ValidationAuthorityImpl) PerformValidation(ctx context.Context, domain string, challenge core.Challenge, authz core.Authorization) ([]core.ValidationRecord, error) {
	logEvent := verificationRequestEvent{
		ID:        authz.ID,
		Requester: authz.RegistrationID,
		Hostname:  domain,
	}
	vStart := va.clk.Now()

	var remoteProbs chan *probs.ProblemDetails
	if remoteVACount := len(va.remoteVAs); remoteVACount > 0 {
		remoteProbs = make(chan *probs.ProblemDetails, remoteVACount)
		go va.performRemoteValidation(ctx, domain, challenge, authz, remoteProbs)
	}

	records, prob := va.validate(ctx, core.AcmeIdentifier{Type: "dns", Value: domain}, challenge, authz)
	challenge.ValidationRecord = records

	// Check for malformed ValidationRecords
	if !challenge.RecordsSane() && prob == nil {
		prob = probs.ServerInternal("Records for validation failed sanity check")
	}

	var problemType string
	if prob != nil {
		problemType = string(prob.Type)
		challenge.Status = core.StatusInvalid
		challenge.Error = prob
		logEvent.Error = prob.Error()
	} else if remoteProbs != nil {
		if !features.Enabled(features.EnforceMultiVA) && features.Enabled(features.MultiVAFullResults) {
			// If we're not going to enforce multi VA but we are logging the
			// differentials then collect and log the remote results in a separate go
			// routine to avoid blocking the primary VA.
			go func() {
				_ = va.processRemoteResults(domain, string(challenge.Type), prob, remoteProbs)
			}()
		} else if features.Enabled(features.EnforceMultiVA) {
			remoteProb := va.processRemoteResults(domain, string(challenge.Type), prob, remoteProbs)
			if remoteProb != nil {
				prob = remoteProb
				challenge.Status = core.StatusInvalid
				challenge.Error = remoteProb
				logEvent.Error = remoteProb.Error()
				va.log.Infof("Validation failed due to remote failures: identifier=%v err=%s",
					domain, remoteProb)
				va.metrics.remoteValidationFailures.Inc()
			} else {
				challenge.Status = core.StatusValid
			}
		}
	} else {
		challenge.Status = core.StatusValid
	}

	logEvent.Challenge = challenge

	validationLatency := time.Since(vStart)
	logEvent.ValidationLatency = validationLatency.Round(time.Millisecond).Seconds()

	va.metrics.validationTime.With(prometheus.Labels{
		"type":        string(challenge.Type),
		"result":      string(challenge.Status),
		"problemType": problemType,
	}).Observe(validationLatency.Seconds())

	va.log.AuditObject("Validation result", logEvent)
	va.log.Infof("Validations: %+v", authz)

	// Try to marshal the validation results and prob (if any) to protocol
	// buffers. We log at this layer instead of leaving it up to gRPC because gRPC
	// doesn't log the actual contents that failed to marshal, making it hard to
	// figure out what's broken.
	if _, err := bgrpc.ValidationResultToPB(records, prob); err != nil {
		va.log.Errf(
			"failed to marshal records %#v and prob %#v to protocol buffer: %v",
			records, prob, err)
	}

	if prob == nil {
		// This is necessary because if we just naively returned prob, it would be a
		// non-nil interface value containing a nil pointer, rather than a nil
		// interface value. See, e.g.
		// https://stackoverflow.com/questions/29138591/hiding-nil-values-understanding-why-golang-fails-here
		return records, nil
	}

	return records, prob
}
