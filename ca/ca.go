package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	cfsslConfig "github.com/cloudflare/cfssl/config"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/ocsp"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	"github.com/jmhodges/clock"
	"github.com/miekg/pkcs11"
	"golang.org/x/net/context"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	csrlib "github.com/letsencrypt/boulder/csr"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

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
	metricSigningError = "SigningError"
	metricHSMError     = metricSigningError + ".HSMError"

	// Increments when CA handles a CSR requesting a "basic" extension:
	// authorityInfoAccess, authorityKeyIdentifier, extKeyUsage, keyUsage,
	// basicConstraints, certificatePolicies, crlDistributionPoints,
	// subjectAlternativeName, subjectKeyIdentifier,
	metricCSRExtensionBasic = "CSRExtensions.Basic"

	// Increments when CA handles a CSR requesting a TLS Feature extension
	metricCSRExtensionTLSFeature = "CSRExtensions.TLSFeature"

	// Increments when CA handles a CSR requesting a TLS Feature extension with
	// an invalid value
	metricCSRExtensionTLSFeatureInvalid = "CSRExtensions.TLSFeatureInvalid"

	// Increments when CA handles a CSR requesting an extension other than those
	// listed above
	metricCSRExtensionOther = "CSRExtensions.Other"
)

type certificateStorage interface {
	AddCertificate(context.Context, []byte, int64, []byte) (string, error)
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
	keyPolicy        goodkey.KeyPolicy
	clk              clock.Clock
	log              blog.Logger
	stats            metrics.Scope
	prefix           int // Prepended to the serial number
	validityPeriod   time.Duration
	maxNames         int
	forceCNFromSAN   bool
	enableMustStaple bool
	signatureCount   *prometheus.CounterVec
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
// from a single issuer (the first first in the issuers slice), and can sign OCSP
// for any of the issuer certificates provided.
func NewCertificateAuthorityImpl(
	config cmd.CAConfig,
	clk clock.Clock,
	stats metrics.Scope,
	issuers []Issuer,
	keyPolicy goodkey.KeyPolicy,
	logger blog.Logger,
) (*CertificateAuthorityImpl, error) {
	var ca *CertificateAuthorityImpl
	var err error

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

	signatureCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "signatures",
			Help: "Number of signatures",
		},
		[]string{"purpose"})
	stats.MustRegister(signatureCount)

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
		signatureCount:   signatureCount,
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
			ca.stats.Inc(metricHSMError, 1)
		} else if cfErr, ok := err.(*cferr.Error); ok {
			ca.stats.Inc(fmt.Sprintf("%s.%d", metricSigningError, cfErr.ErrorCode), 1)
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
					ca.stats.Inc(metricCSRExtensionTLSFeature, 1)
					value, ok := ext.Value.([]byte)
					if !ok {
						return nil, berrors.MalformedError("malformed extension with OID %v", ext.Type)
					} else if !bytes.Equal(value, mustStapleFeatureValue) {
						ca.stats.Inc(metricCSRExtensionTLSFeatureInvalid, 1)
						return nil, berrors.MalformedError("unsupported value for extension with OID %v", ext.Type)
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
		ca.stats.Inc(metricCSRExtensionBasic, 1)
	}

	if hasOther {
		ca.stats.Inc(metricCSRExtensionOther, 1)
	}

	return extensions, nil
}

// GenerateOCSP produces a new OCSP response and returns it
func (ca *CertificateAuthorityImpl) GenerateOCSP(ctx context.Context, xferObj core.OCSPSigningRequest) ([]byte, error) {
	cert, err := x509.ParseCertificate(xferObj.CertDER)
	if err != nil {
		ca.log.AuditErr(err.Error())
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
	if err == nil {
		ca.signatureCount.With(prometheus.Labels{"purpose": "ocsp"}).Inc()
	}
	return ocspResponse, err
}

// IssueCertificate attempts to convert a CSR into a signed Certificate, while
// enforcing all policies. Names (domains) in the CertificateRequest will be
// lowercased before storage.
// Currently it will always sign with the defaultIssuer.
func (ca *CertificateAuthorityImpl) IssueCertificate(ctx context.Context, csr x509.CertificateRequest, regID int64) (core.Certificate, error) {
	emptyCert := core.Certificate{}

	if err := csrlib.VerifyCSR(
		&csr,
		ca.maxNames,
		&ca.keyPolicy,
		ca.PA,
		ca.forceCNFromSAN,
		regID,
	); err != nil {
		ca.log.AuditErr(err.Error())
		return emptyCert, berrors.MalformedError(err.Error())
	}

	requestedExtensions, err := ca.extensionsFromCSR(&csr)
	if err != nil {
		return emptyCert, err
	}

	issuer := ca.defaultIssuer
	notAfter := ca.clk.Now().Add(ca.validityPeriod)

	if issuer.cert.NotAfter.Before(notAfter) {
		err = berrors.InternalServerError("cannot issue a certificate that expires after the issuer certificate")
		ca.log.AuditErr(err.Error())
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
		err = berrors.InternalServerError("failed to generate serial: %s", err)
		ca.log.AuditErr(fmt.Sprintf("Serial randomness failed, err=[%v]", err))
		return emptyCert, err
	}
	serialBigInt := big.NewInt(0)
	serialBigInt = serialBigInt.SetBytes(serialBytes)
	serialHex := core.SerialToString(serialBigInt)

	var profile string
	switch csr.PublicKey.(type) {
	case *rsa.PublicKey:
		profile = ca.rsaProfile
	case *ecdsa.PublicKey:
		profile = ca.ecdsaProfile
	default:
		err = berrors.InternalServerError("unsupported key type %T", csr.PublicKey)
		ca.log.AuditErr(err.Error())
		return emptyCert, err
	}

	// Send the cert off for signing
	req := signer.SignRequest{
		Request: csrPEM,
		Profile: profile,
		Hosts:   csr.DNSNames,
		Subject: &signer.Subject{
			CN: csr.Subject.CommonName,
		},
		Serial:     serialBigInt,
		Extensions: requestedExtensions,
	}
	if !ca.forceCNFromSAN {
		req.Subject.SerialNumber = serialHex
	}

	ca.log.AuditInfo(fmt.Sprintf("Signing: serial=[%s] names=[%s] csr=[%s]",
		serialHex, strings.Join(csr.DNSNames, ", "), hex.EncodeToString(csr.Raw)))

	certPEM, err := issuer.eeSigner.Sign(req)
	ca.noteSignError(err)
	if err != nil {
		err = berrors.InternalServerError("failed to sign certificate: %s", err)
		ca.log.AuditErr(fmt.Sprintf("Signing failed: serial=[%s] err=[%v]", serialHex, err))
		return emptyCert, err
	}
	ca.signatureCount.With(prometheus.Labels{"purpose": "cert"}).Inc()

	if len(certPEM) == 0 {
		err = berrors.InternalServerError("no certificate returned by server")
		ca.log.AuditErr(fmt.Sprintf("PEM empty from Signer: serial=[%s] err=[%v]", serialHex, err))
		return emptyCert, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		err = berrors.InternalServerError("invalid certificate value returned")
		ca.log.AuditErr(fmt.Sprintf("PEM decode error, aborting: serial=[%s] pem=[%s] err=[%v]",
			serialHex, certPEM, err))
		return emptyCert, err
	}
	certDER := block.Bytes

	cert := core.Certificate{
		DER: certDER,
	}

	ca.log.AuditInfo(fmt.Sprintf("Signing success: serial=[%s] names=[%s] csr=[%s] cert=[%s]",
		serialHex, strings.Join(csr.DNSNames, ", "), hex.EncodeToString(csr.Raw),
		hex.EncodeToString(certDER)))

	var ocspResp []byte
	if features.Enabled(features.GenerateOCSPEarly) {
		ocspResp, err = ca.GenerateOCSP(ctx, core.OCSPSigningRequest{
			CertDER: certDER,
			Status:  "good",
		})
		if err != nil {
			err = berrors.InternalServerError(err.Error())
			ca.log.AuditInfo(fmt.Sprintf("OCSP Signing failure: serial=[%s] err=[%s]", serialHex, err))
			// Ignore errors here to avoid orphaning the certificate. The
			// ocsp-updater will look for certs with a zero ocspLastUpdated
			// and generate the initial response in this case.
		}
	}

	// Store the cert with the certificate authority, if provided
	_, err = ca.SA.AddCertificate(ctx, certDER, regID, ocspResp)
	if err != nil {
		err = berrors.InternalServerError(err.Error())
		// Note: This log line is parsed by cmd/orphan-finder. If you make any
		// changes here, you should make sure they are reflected in orphan-finder.
		ca.log.AuditErr(fmt.Sprintf(
			"Failed RPC to store at SA, orphaning certificate: serial=[%s] cert=[%s] err=[%v], regID=[%d]",
			serialHex,
			hex.EncodeToString(certDER),
			err,
			regID,
		))
		return emptyCert, err
	}

	return cert, nil
}
