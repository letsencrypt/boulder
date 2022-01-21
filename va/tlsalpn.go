package va

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/probs"
)

const (
	// ALPN protocol ID for TLS-ALPN-01 challenge
	// https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-01#section-5.2
	ACMETLS1Protocol = "acme-tls/1"
)

var (
	// NOTE: unfortunately another document claimed the OID we were using in draft-ietf-acme-tls-alpn-01
	// for their own extension and IANA chose to assign it early. Because of this we had to increment
	// the id-pe-acmeIdentifier OID. Since there are in the wild implementations that use the original
	// OID we still need to support it until everyone is switched over to the new one.
	// As defined in https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-01#section-5.1
	// id-pe OID + 30 (acmeIdentifier) + 1 (v1)
	IdPeAcmeIdentifierV1Obsolete = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 30, 1}

	// As defined in https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-04#section-5.1
	// id-pe OID + 31 (acmeIdentifier)
	IdPeAcmeIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}
)

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
	return names
}

func (va *ValidationAuthorityImpl) tryGetTLSCerts(ctx context.Context,
	identifier identifier.ACMEIdentifier, challenge core.Challenge,
	tlsConfig *tls.Config) ([]*x509.Certificate, *tls.ConnectionState, []core.ValidationRecord, *probs.ProblemDetails) {

	allAddrs, err := va.getAddrs(ctx, identifier.Value)
	validationRecords := []core.ValidationRecord{
		{
			Hostname:          identifier.Value,
			AddressesResolved: allAddrs,
			Port:              strconv.Itoa(va.tlsPort),
		},
	}
	if err != nil {
		return nil, nil, validationRecords, detailedError(err)
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

		certs, cs, prob := va.getTLSCerts(ctx, address, identifier, challenge, tlsConfig)

		// If there is no problem, return immediately
		if err == nil {
			return certs, cs, validationRecords, prob
		}

		// Otherwise, we note that we tried an address and fall back to trying IPv4
		thisRecord.AddressesTried = append(thisRecord.AddressesTried, thisRecord.AddressUsed)
		va.metrics.ipv4FallbackCounter.Inc()
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
	certs, cs, prob := va.getTLSCerts(ctx, net.JoinHostPort(v4[0].String(), thisRecord.Port),
		identifier, challenge, tlsConfig)
	return certs, cs, validationRecords, prob
}

func (va *ValidationAuthorityImpl) getTLSCerts(
	ctx context.Context,
	hostPort string,
	identifier identifier.ACMEIdentifier,
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
		return nil, nil, probs.Unauthorized(fmt.Sprintf("No certs presented for %s challenge", challenge.Type))
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

func (va *ValidationAuthorityImpl) validateTLSALPN01(ctx context.Context, identifier identifier.ACMEIdentifier, challenge core.Challenge) ([]core.ValidationRecord, *probs.ProblemDetails) {
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

	if cs.NegotiatedProtocol != ACMETLS1Protocol {
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
					"acmeValidationV1 extension not critical", core.ChallengeTypeTLSALPN01)
				return validationRecords, probs.Unauthorized(errText)
			}
			var extValue []byte
			rest, err := asn1.Unmarshal(ext.Value, &extValue)
			if err != nil || len(rest) > 0 || len(h) != len(extValue) {
				errText := fmt.Sprintf("Incorrect validation certificate for %s challenge. "+
					"Malformed acmeValidationV1 extension value", core.ChallengeTypeTLSALPN01)
				return validationRecords, probs.Unauthorized(errText)
			}
			if subtle.ConstantTimeCompare(h[:], extValue) != 1 {
				errText := fmt.Sprintf("Incorrect validation certificate for %s challenge. "+
					"Expected acmeValidationV1 extension value %s for this challenge but got %s",
					core.ChallengeTypeTLSALPN01, hex.EncodeToString(h[:]), hex.EncodeToString(extValue))
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
