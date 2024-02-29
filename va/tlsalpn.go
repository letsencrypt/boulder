package va

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/identifier"
)

const (
	// ALPN protocol ID for TLS-ALPN-01 challenge
	// https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-01#section-5.2
	ACMETLS1Protocol = "acme-tls/1"
)

var (
	// As defined in https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-04#section-5.1
	// id-pe OID + 31 (acmeIdentifier)
	IdPeAcmeIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}
	// OID for the Subject Alternative Name extension, as defined in
	// https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
	IdCeSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// certAltNames collects up all of a certificate's subject names (Subject CN and
// Subject Alternate Names) and reduces them to a unique, sorted set, typically for an
// error message
func certAltNames(cert *x509.Certificate) []string {
	var names []string
	if cert.Subject.CommonName != "" {
		names = append(names, cert.Subject.CommonName)
	}
	names = append(names, cert.DNSNames...)
	names = append(names, cert.EmailAddresses...)
	for _, id := range cert.IPAddresses {
		names = append(names, id.String())
	}
	for _, id := range cert.URIs {
		names = append(names, id.String())
	}
	names = core.UniqueLowerNames(names)
	return names
}

func (va *ValidationAuthorityImpl) tryGetChallengeCert(ctx context.Context,
	identifier identifier.ACMEIdentifier, challenge core.Challenge,
	tlsConfig *tls.Config) (*x509.Certificate, *tls.ConnectionState, core.ValidationRecord, error) {

	allAddrs, resolvers, err := va.getAddrs(ctx, identifier.Value)
	validationRecord := core.ValidationRecord{
		Hostname:          identifier.Value,
		AddressesResolved: allAddrs,
		Port:              strconv.Itoa(va.tlsPort),
		ResolverAddrs:     resolvers,
	}
	if err != nil {
		return nil, nil, validationRecord, err
	}

	// Split the available addresses into v4 and v6 addresses
	v4, v6 := availableAddresses(allAddrs)
	addresses := append(v4, v6...)

	// This shouldn't happen, but be defensive about it anyway
	if len(addresses) < 1 {
		return nil, nil, validationRecord, berrors.MalformedError("no IP addresses found for %q", identifier.Value)
	}

	// If there is at least one IPv6 address then try it first
	if len(v6) > 0 {
		address := net.JoinHostPort(v6[0].String(), validationRecord.Port)
		validationRecord.AddressUsed = v6[0]

		cert, cs, err := va.getChallengeCert(ctx, address, identifier, challenge, tlsConfig)

		// If there is no problem, return immediately
		if err == nil {
			return cert, cs, validationRecord, nil
		}

		// Otherwise, we note that we tried an address and fall back to trying IPv4
		validationRecord.AddressesTried = append(validationRecord.AddressesTried, validationRecord.AddressUsed)
		va.metrics.ipv4FallbackCounter.Inc()
	}

	// If there are no IPv4 addresses and we tried an IPv6 address return
	// an error - there's nothing left to try
	if len(v4) == 0 && len(validationRecord.AddressesTried) > 0 {
		return nil, nil, validationRecord, berrors.MalformedError("Unable to contact %q at %q, no IPv4 addresses to try as fallback",
			validationRecord.Hostname, validationRecord.AddressesTried[0])
	} else if len(v4) == 0 && len(validationRecord.AddressesTried) == 0 {
		// It shouldn't be possible that there are no IPv4 addresses and no previous
		// attempts at an IPv6 address connection but be defensive about it anyway
		return nil, nil, validationRecord, berrors.MalformedError("No IP addresses found for %q", validationRecord.Hostname)
	}

	// Otherwise if there are no IPv6 addresses, or there was an error
	// talking to the first IPv6 address, try the first IPv4 address
	validationRecord.AddressUsed = v4[0]
	cert, cs, err := va.getChallengeCert(ctx, net.JoinHostPort(v4[0].String(), validationRecord.Port),
		identifier, challenge, tlsConfig)
	return cert, cs, validationRecord, err
}

func (va *ValidationAuthorityImpl) getChallengeCert(
	ctx context.Context,
	hostPort string,
	identifier identifier.ACMEIdentifier,
	challenge core.Challenge,
	config *tls.Config,
) (*x509.Certificate, *tls.ConnectionState, error) {
	va.log.Info(fmt.Sprintf("%s [%s] Attempting to validate for %s %s", challenge.Type, identifier, hostPort, config.ServerName))
	// We expect a self-signed challenge certificate, do not verify it here.
	config.InsecureSkipVerify = true

	dialCtx, cancel := context.WithTimeout(ctx, va.singleDialTimeout)
	defer cancel()

	dialer := &tls.Dialer{Config: config}
	conn, err := dialer.DialContext(dialCtx, "tcp", hostPort)
	if err != nil {
		va.log.Infof("%s connection failure for %s. err=[%#v] errStr=[%s]", challenge.Type, identifier, err, err)
		host, _, splitErr := net.SplitHostPort(hostPort)
		if splitErr == nil && net.ParseIP(host) != nil {
			// Wrap the validation error and the IP of the remote host in an
			// IPError so we can display the IP in the problem details returned
			// to the client.
			return nil, nil, ipError{net.ParseIP(host), err}
		}
		return nil, nil, err
	}
	defer conn.Close()

	// tls.Dialer.DialContext guarantees that the *net.Conn it returns is a *tls.Conn.
	cs := conn.(*tls.Conn).ConnectionState()
	certs := cs.PeerCertificates
	if len(certs) == 0 {
		va.log.Infof("%s challenge for %s resulted in no certificates", challenge.Type, identifier.Value)
		return nil, nil, berrors.UnauthorizedError("No certs presented for %s challenge", challenge.Type)
	}
	for i, cert := range certs {
		va.log.AuditInfof("%s challenge for %s received certificate (%d of %d): cert=[%s]",
			challenge.Type, identifier.Value, i+1, len(certs), hex.EncodeToString(cert.Raw))
	}
	return certs[0], &cs, nil
}

func checkExpectedSAN(cert *x509.Certificate, name identifier.ACMEIdentifier) error {
	if len(cert.DNSNames) != 1 {
		return errors.New("wrong number of dNSNames")
	}

	for _, ext := range cert.Extensions {
		if IdCeSubjectAltName.Equal(ext.Id) {
			expectedSANs, err := asn1.Marshal([]asn1.RawValue{
				{Tag: 2, Class: 2, Bytes: []byte(cert.DNSNames[0])},
			})
			if err != nil || !bytes.Equal(expectedSANs, ext.Value) {
				return errors.New("SAN extension does not match expected bytes")
			}
		}
	}

	if !strings.EqualFold(cert.DNSNames[0], name.Value) {
		return errors.New("dNSName does not match expected identifier")
	}

	return nil
}

// Confirm that of the OIDs provided, all of them are in the provided list of
// extensions. Also confirms that of the extensions provided that none are
// repeated. Per RFC8737, allows unexpected extensions.
func checkAcceptableExtensions(exts []pkix.Extension, requiredOIDs []asn1.ObjectIdentifier) error {
	oidSeen := make(map[string]bool)

	for _, ext := range exts {
		if oidSeen[ext.Id.String()] {
			return fmt.Errorf("Extension OID %s seen twice", ext.Id)
		}
		oidSeen[ext.Id.String()] = true
	}

	for _, required := range requiredOIDs {
		if !oidSeen[required.String()] {
			return fmt.Errorf("Required extension OID %s is not present", required)
		}
	}

	return nil
}

func (va *ValidationAuthorityImpl) validateTLSALPN01(ctx context.Context, identifier identifier.ACMEIdentifier, challenge core.Challenge) ([]core.ValidationRecord, error) {
	if identifier.Type != "dns" {
		va.log.Info(fmt.Sprintf("Identifier type for TLS-ALPN-01 was not DNS: %s", identifier))
		return nil, berrors.MalformedError("Identifier type for TLS-ALPN-01 was not DNS")
	}

	cert, cs, tvr, problem := va.tryGetChallengeCert(ctx, identifier, challenge, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{ACMETLS1Protocol},
		ServerName: identifier.Value,
	})
	// Copy the single validationRecord into the slice that we have to return, and
	// get a reference to it so we can modify it if we have to.
	validationRecords := []core.ValidationRecord{tvr}
	validationRecord := &validationRecords[0]
	if problem != nil {
		return validationRecords, problem
	}

	if cs.NegotiatedProtocol != ACMETLS1Protocol {
		return validationRecords, berrors.UnauthorizedError(
			"Cannot negotiate ALPN protocol %q for %s challenge",
			ACMETLS1Protocol,
			core.ChallengeTypeTLSALPN01)
	}

	badCertErr := func(msg string) error {
		hostPort := net.JoinHostPort(validationRecord.AddressUsed.String(), validationRecord.Port)

		return berrors.UnauthorizedError(
			"Incorrect validation certificate for %s challenge. "+
				"Requested %s from %s. %s",
			challenge.Type, identifier.Value, hostPort, msg)
	}

	// The certificate must be self-signed.
	err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil || !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return validationRecords, badCertErr(
			"Received certificate which is not self-signed.")
	}

	// The certificate must have the subjectAltName and acmeIdentifier
	// extensions, and only one of each.
	allowedOIDs := []asn1.ObjectIdentifier{
		IdPeAcmeIdentifier, IdCeSubjectAltName,
	}
	err = checkAcceptableExtensions(cert.Extensions, allowedOIDs)
	if err != nil {
		return validationRecords, badCertErr(
			fmt.Sprintf("Received certificate with unexpected extensions: %q", err))
	}

	// The certificate returned must have a subjectAltName extension containing
	// only the dNSName being validated and no other entries.
	err = checkExpectedSAN(cert, identifier)
	if err != nil {
		names := strings.Join(certAltNames(cert), ", ")
		return validationRecords, badCertErr(
			fmt.Sprintf("Received certificate with unexpected identifiers (%q): %q", names, err))
	}

	// Verify key authorization in acmeValidation extension
	h := sha256.Sum256([]byte(challenge.ProvidedKeyAuthorization))
	for _, ext := range cert.Extensions {
		if IdPeAcmeIdentifier.Equal(ext.Id) {
			va.metrics.tlsALPNOIDCounter.WithLabelValues(IdPeAcmeIdentifier.String()).Inc()
			if !ext.Critical {
				return validationRecords, badCertErr(
					"Received certificate with acmeValidationV1 extension that is not Critical.")
			}
			var extValue []byte
			rest, err := asn1.Unmarshal(ext.Value, &extValue)
			if err != nil || len(rest) > 0 || len(h) != len(extValue) {
				return validationRecords, badCertErr(
					"Received certificate with malformed acmeValidationV1 extension value.")
			}
			if subtle.ConstantTimeCompare(h[:], extValue) != 1 {
				return validationRecords, badCertErr(fmt.Sprintf(
					"Received certificate with acmeValidationV1 extension value %s but expected %s.",
					hex.EncodeToString(extValue),
					hex.EncodeToString(h[:]),
				))
			}
			// We were successful, so record the negotiated key exchange mechanism in
			// the validationRecord.
			// TODO(#7321): Remove this when we have collected enough data.
			validationRecord.UsedRSAKEX = usedRSAKEX(cs.CipherSuite)
			return validationRecords, nil
		}
	}

	return validationRecords, badCertErr(
		"Received certificate with no acmeValidationV1 extension.")
}
