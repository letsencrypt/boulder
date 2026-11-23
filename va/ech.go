package va

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	"github.com/miekg/dns"

	"github.com/letsencrypt/boulder/core"
)

// supportedMandatoryKeys are the SvcParamKeys that may appear in an HTTPS
// record's "mandatory" list without making us ignore the record. We don't
// process all of these (e.g. we ignore the IP hints), but we recognize their
// names and we know they don't affect our behavior.
var supportedMandatoryKeys = map[dns.SVCBKey]bool{
	dns.SVCB_ALPN:            true,
	dns.SVCB_NO_DEFAULT_ALPN: true,
	dns.SVCB_PORT:            true,
	dns.SVCB_ECHCONFIG:       true,
	dns.SVCB_IPV4HINT:        true,
	dns.SVCB_IPV6HINT:        true,
}

// echConfigListFromHTTPS returns the ECHConfigList from the most preferred of
// the given HTTPS records that applies to a TLS connection to the records'
// owner on the given port, or nil if there is none.
func echConfigListFromHTTPS(rrs []*dns.HTTPS, port int) []byte {
	var echConfigList []byte
	var bestPriority uint16
	for _, rr := range rrs {
		// RFC 9460, Section 1.2: SvcPriority... A value of 0 indicates AliasMode.
		//
		// RFC 9460, Section 2.4.1: If an RRset contains a record in AliasMode,
		// the recipient MUST ignore any ServiceMode records in the set.
		//
		// An AliasMode record can't include ECH configuration, so ignore everything.
		if rr.Priority == 0 {
			return nil
		}

		// RFC 9460, Section 2.5.2: if TargetName has the value ".", then the owner
		// name of this record MUST be used as the effective TargetName.
		//
		// Since we're querying for ECH directly at the domain we're validating, we
		// only care about records whose target is the queried-for domain, whether
		// given as "." or spelled out.
		if rr.Target != "." && dns.CanonicalName(rr.Target) != dns.CanonicalName(rr.Hdr.Name) {
			continue
		}

		ech := echFromServiceRecord(rr, port)
		if len(ech) == 0 {
			continue
		}

		// RFC 9460, Section 3: Sort the records by ascending SvcPriority.
		if echConfigList == nil || rr.Priority < bestPriority {
			echConfigList = ech
			bestPriority = rr.Priority
		}
	}
	return echConfigList
}

// echFromServiceRecord returns the ech SvcParam of a ServiceMode HTTPS record,
// or nil if the record doesn't have one, applies to the wrong port, or has
// mandatory SvcParams that we don't recognize.
func echFromServiceRecord(rr *dns.HTTPS, port int) []byte {
	var ech []byte
	for _, kv := range rr.Value {
		switch v := kv.(type) {
		case *dns.SVCBPort:
			if int(v.Port) != port {
				return nil
			}
		case *dns.SVCBMandatory:
			for _, key := range v.Code {
				if !supportedMandatoryKeys[key] {
					return nil
				}
			}
		case *dns.SVCBECHConfig:
			ech = v.ECH
		}
	}
	return ech
}

// dialTLSWithECH uses dialTLS to make a connection to addr and perform a TLS
// handshake, and returns the resulting connection object. If an ECH config
// is provided, the tlsConfig is augmented to include it. If the ECH config is
// rejected and the server supplies a retry config, attempts one retry with the
// supplied config. If the handshake fails for some other reason, attempts one
// fallback without ECH.
func (va *ValidationAuthorityImpl) dialTLSWithECH(
	ctx context.Context,
	dialTLS tlsDialerFunc,
	addr string,
	tlsConfig *tls.Config,
	echConfigList []byte,
) (*tls.Conn, core.ECHStatus, error) {
	// Attempt 0: just fall through to a TLS handshake if no ECH config is given.
	if len(echConfigList) == 0 {
		conn, err := dialTLS(ctx, "tcp", addr, tlsConfig)
		return conn, "", err
	}

	// Attempt 1: try an ECH handshake, and exit on success or non-retryable failure.
	conn, err := va.echHandshake(ctx, dialTLS, addr, tlsConfig, echConfigList)
	if err != nil && !echFallbackErr(ctx, err) {
		// The dial failed or we ran out of time, so we learned nothing about ECH.
		return nil, "", err
	} else if err == nil {
		va.metrics.echHandshakes.WithLabelValues(string(core.ECHAccepted)).Inc()
		return conn, core.ECHAccepted, nil
	}

	// Attempt 2: if and only if the error was an explicit ECH rejection and
	// included a retry config list, attempt a retry with that ECH config.
	status := core.ECHFailed
	rejection, ok := errors.AsType[*tls.ECHRejectionError](err)
	if ok {
		status = core.ECHRejected
		if len(rejection.RetryConfigList) > 0 {
			conn, err = va.echHandshake(ctx, dialTLS, addr, tlsConfig, rejection.RetryConfigList)
			if err == nil {
				va.metrics.echHandshakes.WithLabelValues(string(core.ECHAccepted) + "_retry").Inc()
				return conn, core.ECHAccepted, nil
			}
		}
	}
	va.metrics.echHandshakes.WithLabelValues(string(status)).Inc()
	if !echFallbackErr(ctx, err) {
		return nil, status, err
	}

	// Attempt 3: whether it was the first or second ECH attempt that failed,
	// we're willing to fall back to a TLS handshake with no ECH.
	conn, err = dialTLS(ctx, "tcp", addr, tlsConfig)
	return conn, status, err
}

// echHandshake is dialTLS using ECH with the given config list. It fails
// unless the server accepts ECH.
func (va *ValidationAuthorityImpl) echHandshake(
	ctx context.Context,
	dialTLS tlsDialerFunc,
	addr string,
	tlsConfig *tls.Config,
	echConfigList []byte,
) (*tls.Conn, error) {
	tlsConfig = tlsConfig.Clone()
	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.EncryptedClientHelloConfigList = echConfigList
	tlsConfig.EncryptedClientHelloRejectionVerify = func(tls.ConnectionState) error { return nil }

	conn, err := dialTLS(ctx, "tcp", addr, tlsConfig)
	if err != nil {
		return nil, err
	}
	if !conn.ConnectionState().ECHAccepted {
		_ = conn.Close()
		return nil, errors.New("server did not accept ECH")
	}
	return conn, nil
}

// echFallbackErr returns true if err, from a failed ECH handshake, is worth
// retrying without ECH. A failed dial would likely just repeat, but a handshake
// timeout may be caused by ECH itself, e.g. a middlebox that drops ECH
// ClientHellos.
func echFallbackErr(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	opErr, ok := errors.AsType[*net.OpError](err)
	if ok && opErr.Op == "dial" {
		return false
	}
	return true
}
