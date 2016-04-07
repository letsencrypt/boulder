// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	cfsslConfig "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/config"
	cferr "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/errors"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/ocsp"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/signer"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/signer/local"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/pkcs11"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

// This map is used to detect algorithms in crypto/x509 that
// are no longer considered sufficiently strong.
// * No MD2, MD5, or SHA-1
// * No DSA
//
// SHA1WithRSA is allowed because there's still a fair bit of it
// out there, but we should try to remove it soon.
var badSignatureAlgorithms = map[x509.SignatureAlgorithm]bool{
	x509.UnknownSignatureAlgorithm: true,
	x509.MD2WithRSA:                true,
	x509.MD5WithRSA:                true,
	x509.DSAWithSHA1:               true,
	x509.DSAWithSHA256:             true,
	x509.ECDSAWithSHA1:             true,
}

// Miscellaneous PKIX OIDs that we need to refer to
var (
	// X.509 Extensions
	oidAuthorityInfoAccess    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidAuthorityKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidBasicConstraints       = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidCertificatePolicies    = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidCrlDistributionPoints  = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidExtKeyUsage            = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidKeyUsage               = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidSubjectAltName         = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidSubjectKeyIdentifier   = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidTLSFeature             = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}

	// CSR attribute requesting extensions
	oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
)

// OID and fixed value for the "must staple" variant of the TLS Feature
// extension:
//
//  Features ::= SEQUENCE OF INTEGER                  [RFC7633]
//  enum { ... status_request(5) ...} ExtensionType;  [RFC6066]
//
// DER Encoding:
//  30 03 - SEQUENCE (3 octets)
//  |-- 02 01 - INTEGER (1 octet)
//  |   |-- 05 - 5
var (
	mustStapleFeatureValue = []byte{0x30, 0x03, 0x02, 0x01, 0x05}
	mustStapleExtension    = signer.Extension{
		ID:       cfsslConfig.OID(oidTLSFeature),
		Critical: false,
		Value:    hex.EncodeToString(mustStapleFeatureValue),
	}
)

// Metrics for CA statistics
const (
	// Increments when CA observes an HSM or signing error
	metricSigningError = "CA.SigningError"
	metricHSMError     = metricSigningError + ".HSMError"

	// Increments when CA handles a CSR requesting a "basic" extension:
	// authorityInfoAccess, authorityKeyIdentifier, extKeyUsage, keyUsage,
	// basicConstraints, certificatePolicies, crlDistributionPoints,
	// subjectAlternativeName, subjectKeyIdentifier,
	metricCSRExtensionBasic = "CA.CSRExtensions.Basic"

	// Increments when CA handles a CSR requesting a TLS Feature extension
	metricCSRExtensionTLSFeature = "CA.CSRExtensions.TLSFeature"

	// Increments when CA handles a CSR requesting a TLS Feature extension with
	// an invalid value
	metricCSRExtensionTLSFeatureInvalid = "CA.CSRExtensions.TLSFeatureInvalid"

	// Increments when CA handles a CSR requesting an extension other than those
	// listed above
	metricCSRExtensionOther = "CA.CSRExtensions.Other"

	// Maximum length allowed for the common name. RFC 5280
	maxCNLength = 64
)

type certificateStorage interface {
	AddCertificate([]byte, int64) (string, error)
}

// CertificateAuthorityImpl represents a CA that signs certificates, CRLs, and
// OCSP responses.
type CertificateAuthorityImpl struct {
	rsaProfile   string
	ecdsaProfile string
	// A map from issuer cert common name to an internalIssuer struct
	issuers map[string]*internalIssuer
	// The common name of the default issuer cert
	defaultIssuer    *internalIssuer
	SA               certificateStorage
	PA               core.PolicyAuthority
	Publisher        core.Publisher
	keyPolicy        core.KeyPolicy
	clk              clock.Clock
	log              *blog.AuditLogger
	stats            statsd.Statter
	prefix           int // Prepended to the serial number
	validityPeriod   time.Duration
	maxNames         int
	forceCNFromSAN   bool
	enableMustStaple bool
}

// Issuer represents a single issuer certificate, along with its key.
type Issuer struct {
	Signer crypto.Signer
	Cert   *x509.Certificate
}

// internalIssuer represents the fully initialized internal state for a single
// issuer, including the cfssl signer and OCSP signer objects.
type internalIssuer struct {
	cert       *x509.Certificate
	eeSigner   signer.Signer
	ocspSigner ocsp.Signer
}

func makeInternalIssuers(
	issuers []Issuer,
	policy *cfsslConfig.Signing,
	lifespanOCSP time.Duration,
) (map[string]*internalIssuer, error) {
	if len(issuers) == 0 {
		return nil, errors.New("No issuers specified.")
	}
	internalIssuers := make(map[string]*internalIssuer)
	for _, iss := range issuers {
		if iss.Cert == nil || iss.Signer == nil {
			return nil, errors.New("Issuer with nil cert or signer specified.")
		}
		eeSigner, err := local.NewSigner(iss.Signer, iss.Cert, x509.SHA256WithRSA, policy)
		if err != nil {
			return nil, err
		}

		// Set up our OCSP signer. Note this calls for both the issuer cert and the
		// OCSP signing cert, which are the same in our case.
		ocspSigner, err := ocsp.NewSigner(iss.Cert, iss.Cert, iss.Signer, lifespanOCSP)
		if err != nil {
			return nil, err
		}
		cn := iss.Cert.Subject.CommonName
		if internalIssuers[cn] != nil {
			return nil, errors.New("Multiple issuer certs with the same CommonName are not supported")
		}
		internalIssuers[cn] = &internalIssuer{
			cert:       iss.Cert,
			eeSigner:   eeSigner,
			ocspSigner: ocspSigner,
		}
	}
	return internalIssuers, nil
}

// NewCertificateAuthorityImpl creates a CA instance that can sign certificates
// from a single issuer (the first first in the issers slice), and can sign OCSP
// for any of the issuer certificates provided.
func NewCertificateAuthorityImpl(
	config cmd.CAConfig,
	clk clock.Clock,
	stats statsd.Statter,
	issuers []Issuer,
	keyPolicy core.KeyPolicy,
) (*CertificateAuthorityImpl, error) {
	var ca *CertificateAuthorityImpl
	var err error
	logger := blog.GetAuditLogger()
	logger.Notice("Certificate Authority Starting")

	if config.SerialPrefix <= 0 || config.SerialPrefix >= 256 {
		err = errors.New("Must have a positive non-zero serial prefix less than 256 for CA.")
		return nil, err
	}

	// CFSSL requires processing JSON configs through its own LoadConfig, so we
	// serialize and then deserialize.
	cfsslJSON, err := json.Marshal(config.CFSSL)
	if err != nil {
		return nil, err
	}
	cfsslConfigObj, err := cfsslConfig.LoadConfig(cfsslJSON)
	if err != nil {
		return nil, err
	}

	if config.LifespanOCSP.Duration == 0 {
		return nil, errors.New("Config must specify an OCSP lifespan period.")
	}

	internalIssuers, err := makeInternalIssuers(
		issuers,
		cfsslConfigObj.Signing,
		config.LifespanOCSP.Duration)
	if err != nil {
		return nil, err
	}
	defaultIssuer := internalIssuers[issuers[0].Cert.Subject.CommonName]

	rsaProfile := config.RSAProfile
	ecdsaProfile := config.ECDSAProfile

	if rsaProfile == "" || ecdsaProfile == "" {
		return nil, errors.New("must specify rsaProfile and ecdsaProfile")
	}

	ca = &CertificateAuthorityImpl{
		issuers:          internalIssuers,
		defaultIssuer:    defaultIssuer,
		rsaProfile:       rsaProfile,
		ecdsaProfile:     ecdsaProfile,
		prefix:           config.SerialPrefix,
		clk:              clk,
		log:              logger,
		stats:            stats,
		keyPolicy:        keyPolicy,
		forceCNFromSAN:   !config.DoNotForceCN, // Note the inversion here
		enableMustStaple: config.EnableMustStaple,
	}

	if config.Expiry == "" {
		return nil, errors.New("Config must specify an expiry period.")
	}
	ca.validityPeriod, err = time.ParseDuration(config.Expiry)
	if err != nil {
		return nil, err
	}

	ca.maxNames = config.MaxNames

	return ca, nil
}

// noteSignError is called after operations that may cause a CFSSL
// or PKCS11 signing error.
func (ca *CertificateAuthorityImpl) noteSignError(err error) {
	if err != nil {
		if _, ok := err.(*pkcs11.Error); ok {
			ca.stats.Inc(metricHSMError, 1, 1.0)
		} else if cfErr, ok := err.(*cferr.Error); ok {
			ca.stats.Inc(fmt.Sprintf("%s.%d", metricSigningError, cfErr.ErrorCode), 1, 1.0)
		}
	}
	return
}

// Extract supported extensions from a CSR.  The following extensions are
// currently supported:
//
// * 1.3.6.1.5.5.7.1.24 - TLS Feature [RFC7633], with the "must staple" value.
//                        Any other value will result in an error.
//
// Other requested extensions are silently ignored.
func (ca *CertificateAuthorityImpl) extensionsFromCSR(csr *x509.CertificateRequest) ([]signer.Extension, error) {
	extensions := []signer.Extension{}

	extensionSeen := map[string]bool{}
	hasBasic := false
	hasOther := false

	for _, attr := range csr.Attributes {
		if !attr.Type.Equal(oidExtensionRequest) {
			continue
		}

		for _, extList := range attr.Value {
			for _, ext := range extList {
				if extensionSeen[ext.Type.String()] {
					// Ignore duplicate certificate extensions
					continue
				}
				extensionSeen[ext.Type.String()] = true

				switch {
				case ext.Type.Equal(oidTLSFeature):
					ca.stats.Inc(metricCSRExtensionTLSFeature, 1, 1.0)
					value, ok := ext.Value.([]byte)
					if !ok {
						msg := fmt.Sprintf("Malformed extension with OID %v", ext.Type)
						return nil, core.MalformedRequestError(msg)
					} else if !bytes.Equal(value, mustStapleFeatureValue) {
						msg := fmt.Sprintf("Unsupported value for extension with OID %v", ext.Type)
						ca.stats.Inc(metricCSRExtensionTLSFeatureInvalid, 1, 1.0)
						return nil, core.MalformedRequestError(msg)
					}

					if ca.enableMustStaple {
						extensions = append(extensions, mustStapleExtension)
					}
				case ext.Type.Equal(oidAuthorityInfoAccess),
					ext.Type.Equal(oidAuthorityKeyIdentifier),
					ext.Type.Equal(oidBasicConstraints),
					ext.Type.Equal(oidCertificatePolicies),
					ext.Type.Equal(oidCrlDistributionPoints),
					ext.Type.Equal(oidExtKeyUsage),
					ext.Type.Equal(oidKeyUsage),
					ext.Type.Equal(oidSubjectAltName),
					ext.Type.Equal(oidSubjectKeyIdentifier):
					hasBasic = true
				default:
					hasOther = true
				}
			}
		}
	}

	if hasBasic {
		ca.stats.Inc(metricCSRExtensionBasic, 1, 1.0)
	}

	if hasOther {
		ca.stats.Inc(metricCSRExtensionOther, 1, 1.0)
	}

	return extensions, nil
}

// GenerateOCSP produces a new OCSP response and returns it
func (ca *CertificateAuthorityImpl) GenerateOCSP(xferObj core.OCSPSigningRequest) ([]byte, error) {
	cert, err := x509.ParseCertificate(xferObj.CertDER)
	if err != nil {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		ca.log.AuditErr(err)
		return nil, err
	}

	signRequest := ocsp.SignRequest{
		Certificate: cert,
		Status:      xferObj.Status,
		Reason:      int(xferObj.Reason),
		RevokedAt:   xferObj.RevokedAt,
	}

	cn := cert.Issuer.CommonName
	issuer := ca.issuers[cn]
	if issuer == nil {
		return nil, fmt.Errorf("This CA doesn't have an issuer cert with CommonName %q", cn)
	}

	err = cert.CheckSignatureFrom(issuer.cert)
	if err != nil {
		return nil, fmt.Errorf("GenerateOCSP was asked to sign OCSP for cert "+
			"%s from %q, but the cert's signature was not valid: %s.",
			core.SerialToString(cert.SerialNumber), cn, err)
	}

	ocspResponse, err := issuer.ocspSigner.Sign(signRequest)
	ca.noteSignError(err)
	return ocspResponse, err
}

// IssueCertificate attempts to convert a CSR into a signed Certificate, while
// enforcing all policies. Names (domains) in the CertificateRequest will be
// lowercased before storage.
// Currently it will always sign with the defaultIssuer.
func (ca *CertificateAuthorityImpl) IssueCertificate(csr x509.CertificateRequest, regID int64) (core.Certificate, error) {
	emptyCert := core.Certificate{}

	key, ok := csr.PublicKey.(crypto.PublicKey)
	if !ok {
		err := core.MalformedRequestError("Invalid public key in CSR.")
		// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
		ca.log.AuditErr(err)
		return emptyCert, err
	}
	if err := ca.keyPolicy.GoodKey(key); err != nil {
		err = core.MalformedRequestError(fmt.Sprintf("Invalid public key in CSR: %s", err.Error()))
		// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
		ca.log.AuditErr(err)
		return emptyCert, err
	}
	if badSignatureAlgorithms[csr.SignatureAlgorithm] {
		err := core.MalformedRequestError("Invalid signature algorithm in CSR")
		// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
		ca.log.AuditErr(err)
		return emptyCert, err
	}

	// Pull hostnames from CSR
	// Authorization is checked by the RA
	commonName := ""
	hostNames := make([]string, len(csr.DNSNames))
	copy(hostNames, csr.DNSNames)

	if len(csr.Subject.CommonName) > 0 {
		commonName = strings.ToLower(csr.Subject.CommonName)
		hostNames = append(hostNames, commonName)
	}

	if len(hostNames) == 0 {
		err := core.MalformedRequestError("Cannot issue a certificate without a hostname.")
		// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
		ca.log.AuditErr(err)
		return emptyCert, err
	}

	// Collapse any duplicate names.  Note that this operation may re-order the names
	hostNames = core.UniqueLowerNames(hostNames)

	if ca.forceCNFromSAN && commonName == "" {
		commonName = hostNames[0]
	}

	if len(commonName) > maxCNLength {
		msg := fmt.Sprintf("Common name was longer than 64 bytes, was %d",
			len(csr.Subject.CommonName))
		err := core.MalformedRequestError(msg)
		// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
		ca.log.AuditErr(err)
		return emptyCert, err
	}

	if ca.maxNames > 0 && len(hostNames) > ca.maxNames {
		err := core.MalformedRequestError(fmt.Sprintf("Certificate request has %d names, maximum is %d.", len(hostNames), ca.maxNames))
		ca.log.WarningErr(err)
		return emptyCert, err
	}

	// Verify that names are allowed by policy
	var badNames []string
	for _, name := range hostNames {
		identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: name}
		if err := ca.PA.WillingToIssue(identifier, regID); err != nil {
			ca.log.AuditErr(err)
			badNames = append(badNames, name)
		}
	}
	if len(badNames) > 0 {
		err := core.MalformedRequestError(fmt.Sprintf("Policy forbids issuing for: %s", strings.Join(badNames, ", ")))
		// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
		ca.log.AuditErr(err)
		return emptyCert, err
	}

	requestedExtensions, err := ca.extensionsFromCSR(&csr)
	if err != nil {
		return emptyCert, err
	}

	issuer := ca.defaultIssuer
	notAfter := ca.clk.Now().Add(ca.validityPeriod)

	if issuer.cert.NotAfter.Before(notAfter) {
		err = core.InternalServerError("Cannot issue a certificate that expires after the issuer certificate.")
		// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
		ca.log.AuditErr(err)
		return emptyCert, err
	}

	// Convert the CSR to PEM
	csrPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	}))

	// We want 136 bits of random number, plus an 8-bit instance id prefix.
	const randBits = 136
	serialBytes := make([]byte, randBits/8+1)
	serialBytes[0] = byte(ca.prefix)
	_, err = rand.Read(serialBytes[1:])
	if err != nil {
		err = core.InternalServerError(err.Error())
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		ca.log.AuditErr(fmt.Errorf("Serial randomness failed, err=[%v]", err))
		return emptyCert, err
	}
	serialBigInt := big.NewInt(0)
	serialBigInt = serialBigInt.SetBytes(serialBytes)
	serialHex := core.SerialToString(serialBigInt)

	var profile string
	switch key.(type) {
	case *rsa.PublicKey:
		profile = ca.rsaProfile
	case *ecdsa.PublicKey:
		profile = ca.ecdsaProfile
	default:
		err = core.InternalServerError(fmt.Sprintf("unsupported key type %T", key))
		// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
		ca.log.AuditErr(err)
		return emptyCert, err
	}

	// Send the cert off for signing
	req := signer.SignRequest{
		Request: csrPEM,
		Profile: profile,
		Hosts:   hostNames,
		Subject: &signer.Subject{
			CN: commonName,
		},
		Serial:     serialBigInt,
		Extensions: requestedExtensions,
	}
	if !ca.forceCNFromSAN {
		req.Subject.SerialNumber = serialHex
	}

	ca.log.AuditNotice(fmt.Sprintf("Signing: serial=[%s] names=[%s] csr=[%s]",
		serialHex, strings.Join(hostNames, ", "), csrPEM))

	certPEM, err := issuer.eeSigner.Sign(req)
	ca.noteSignError(err)
	if err != nil {
		err = core.InternalServerError(err.Error())
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		ca.log.AuditErr(fmt.Errorf("Signing failed: serial=[%s] err=[%v]", serialHex, err))
		return emptyCert, err
	}

	ca.log.AuditNotice(fmt.Sprintf("Signing success: serial=[%s] names=[%s] csr=[%s] pem=[%s]",
		serialHex, strings.Join(hostNames, ", "), csrPEM,
		certPEM))

	if len(certPEM) == 0 {
		err = core.InternalServerError("No certificate returned by server")
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		ca.log.AuditErr(fmt.Errorf("PEM empty from Signer: serial=[%s] err=[%v]", serialHex, err))
		return emptyCert, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		err = core.InternalServerError("Invalid certificate value returned")
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		ca.log.AuditErr(fmt.Errorf("PEM decode error, aborting: serial=[%s] pem=[%s] err=[%v]",
			serialHex, certPEM, err))
		return emptyCert, err
	}
	certDER := block.Bytes

	cert := core.Certificate{
		DER: certDER,
	}

	// This is one last check for uncaught errors
	if err != nil {
		err = core.InternalServerError(err.Error())
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		ca.log.AuditErr(fmt.Errorf("Uncaught error, aborting: serial=[%s] pem=[%s] err=[%v]",
			serialHex, certPEM, err))
		return emptyCert, err
	}

	// Store the cert with the certificate authority, if provided
	_, err = ca.SA.AddCertificate(certDER, regID)
	if err != nil {
		err = core.InternalServerError(err.Error())
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		ca.log.AuditErr(fmt.Errorf(
			"Failed RPC to store at SA, orphaning certificate: serial=[%s] b64der=[%s] err=[%v], regID=[%d]",
			serialHex,
			base64.StdEncoding.EncodeToString(certDER),
			err,
			regID,
		))
		return emptyCert, err
	}

	// Submit the certificate to any configured CT logs
	go ca.Publisher.SubmitToCT(certDER)

	// Do not return an err at this point; caller must know that the Certificate
	// was issued. (Also, it should be impossible for err to be non-nil here)
	return cert, nil
}
