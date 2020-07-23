package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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

	"github.com/beeker1121/goque"
	cfsslConfig "github.com/cloudflare/cfssl/config"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	"github.com/jmhodges/clock"
	"github.com/miekg/pkcs11"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"

	ca_config "github.com/letsencrypt/boulder/ca/config"
	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	csrlib "github.com/letsencrypt/boulder/csr"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	blog "github.com/letsencrypt/boulder/log"
	sapb "github.com/letsencrypt/boulder/sa/proto"
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

	// https://tools.ietf.org/html/rfc6962#section-3.1
	ctPoisonExtension = signer.Extension{
		ID:       cfsslConfig.OID(signer.CTPoisonOID),
		Critical: true,
		Value:    "0500", // ASN.1 DER NULL, Hex encoded.
	}
)

// Metrics for CA statistics
const (
	csrExtensionCategory          = "category"
	csrExtensionBasic             = "basic"
	csrExtensionTLSFeature        = "tls-feature"
	csrExtensionTLSFeatureInvalid = "tls-feature-invalid"
	csrExtensionOther             = "other"
)

type certificateStorage interface {
	AddCertificate(context.Context, []byte, int64, []byte, *time.Time) (string, error)
	GetCertificate(context.Context, string) (core.Certificate, error)
	AddPrecertificate(ctx context.Context, req *sapb.AddCertificateRequest) (*corepb.Empty, error)
	AddSerial(ctx context.Context, req *sapb.AddSerialRequest) (*corepb.Empty, error)
}

type certificateType string

const (
	precertType = certificateType("precertificate")
	certType    = certificateType("certificate")
)

// CertificateAuthorityImpl represents a CA that signs certificates, CRLs, and
// OCSP responses.
type CertificateAuthorityImpl struct {
	rsaProfile   string
	ecdsaProfile string
	// A map from issuer cert common name to an internalIssuer struct
	issuers map[string]*internalIssuer
	// A map from issuer ID to internalIssuer
	idToIssuer map[int64]*internalIssuer
	// The common name of the default issuer cert
	defaultIssuer      *internalIssuer
	sa                 certificateStorage
	pa                 core.PolicyAuthority
	keyPolicy          goodkey.KeyPolicy
	clk                clock.Clock
	log                blog.Logger
	prefix             int // Prepended to the serial number
	validityPeriod     time.Duration
	backdate           time.Duration
	maxNames           int
	forceCNFromSAN     bool
	signatureCount     *prometheus.CounterVec
	csrExtensionCount  *prometheus.CounterVec
	orphanCount        *prometheus.CounterVec
	adoptedOrphanCount *prometheus.CounterVec
	signErrorCounter   *prometheus.CounterVec
	orphanQueue        *goque.Queue
	ocspLifetime       time.Duration
}

// Issuer represents a single issuer certificate, along with its key.
type Issuer struct {
	Signer crypto.Signer
	Cert   *x509.Certificate
}

// localSigner is an interface describing the functions of a cfssl.local.Signer
// that the Boulder CA uses. It allows mocking the local.Signer in unit tests.
type localSigner interface {
	Sign(signer.SignRequest) ([]byte, error)
	SignFromPrecert(*x509.Certificate, []ct.SignedCertificateTimestamp) ([]byte, error)
}

// internalIssuer represents the fully initialized internal state for a single
// issuer, including the cfssl signer and OCSP signer objects.
type internalIssuer struct {
	cert       *x509.Certificate
	eeSigner   localSigner
	ocspSigner crypto.Signer
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

		cn := iss.Cert.Subject.CommonName
		if internalIssuers[cn] != nil {
			return nil, errors.New("Multiple issuer certs with the same CommonName are not supported")
		}
		internalIssuers[cn] = &internalIssuer{
			cert:       iss.Cert,
			eeSigner:   eeSigner,
			ocspSigner: iss.Signer,
		}
	}
	return internalIssuers, nil
}

// idForIssuer generates a stable ID for an issuer certificate. This
// is used for identifying which issuer issued a certificate in the
// certificateStatus table.
func idForIssuer(cert *x509.Certificate) int64 {
	h := sha256.Sum256(cert.Raw)
	return big.NewInt(0).SetBytes(h[:4]).Int64()
}

// NewCertificateAuthorityImpl creates a CA instance that can sign certificates
// from a single issuer (the first first in the issuers slice), and can sign OCSP
// for any of the issuer certificates provided.
func NewCertificateAuthorityImpl(
	config ca_config.CAConfig,
	sa certificateStorage,
	pa core.PolicyAuthority,
	clk clock.Clock,
	stats prometheus.Registerer,
	issuers []Issuer,
	keyPolicy goodkey.KeyPolicy,
	logger blog.Logger,
	orphanQueue *goque.Queue,
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

	for _, profile := range cfsslConfigObj.Signing.Profiles {
		if len(profile.IssuerURL) > 1 {
			return nil, errors.New("only one issuer_url supported")
		}
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

	csrExtensionCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "csr_extensions",
			Help: "Number of CSRs with extensions of the given category",
		},
		[]string{csrExtensionCategory})
	stats.MustRegister(csrExtensionCount)

	signatureCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "signatures",
			Help: "Number of signatures",
		},
		[]string{"purpose"})
	stats.MustRegister(signatureCount)

	orphanCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "orphans",
			Help: "Number of orphaned certificates labelled by type (precert, cert)",
		},
		[]string{"type"})
	stats.MustRegister(orphanCount)

	adoptedOrphanCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "adopted_orphans",
			Help: "Number of orphaned certificates adopted from the orphan queue by type (precert, cert)",
		},
		[]string{"type"})
	stats.MustRegister(adoptedOrphanCount)

	signErrorCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "signature_errors",
		Help: "A counter of signature errors labelled by error type",
	}, []string{"type"})
	stats.MustRegister(signErrorCounter)

	ca = &CertificateAuthorityImpl{
		sa:                 sa,
		pa:                 pa,
		issuers:            internalIssuers,
		defaultIssuer:      defaultIssuer,
		rsaProfile:         rsaProfile,
		ecdsaProfile:       ecdsaProfile,
		prefix:             config.SerialPrefix,
		clk:                clk,
		log:                logger,
		keyPolicy:          keyPolicy,
		forceCNFromSAN:     !config.DoNotForceCN, // Note the inversion here
		signatureCount:     signatureCount,
		csrExtensionCount:  csrExtensionCount,
		orphanCount:        orphanCount,
		adoptedOrphanCount: adoptedOrphanCount,
		orphanQueue:        orphanQueue,
		ocspLifetime:       config.LifespanOCSP.Duration,
		signErrorCounter:   signErrorCounter,
	}

	ca.idToIssuer = make(map[int64]*internalIssuer)
	for _, ii := range ca.issuers {
		id := idForIssuer(ii.cert)
		ca.idToIssuer[id] = ii
	}

	if config.Expiry == "" {
		return nil, errors.New("Config must specify an expiry period.")
	}
	ca.validityPeriod, err = time.ParseDuration(config.Expiry)
	if err != nil {
		return nil, err
	}

	// TODO(briansmith): Make the backdate setting mandatory after the
	// production ca.json has been updated to include it. Until then, manually
	// default to 1h, which is the backdating duration we currently use.
	ca.backdate = config.Backdate.Duration
	if ca.backdate == 0 {
		ca.backdate = time.Hour
	}

	ca.maxNames = config.MaxNames

	return ca, nil
}

// noteSignError is called after operations that may cause a CFSSL
// or PKCS11 signing error.
func (ca *CertificateAuthorityImpl) noteSignError(err error) {
	if _, ok := err.(*pkcs11.Error); ok {
		ca.signErrorCounter.WithLabelValues("HSM").Inc()
	} else if cfErr, ok := err.(*cferr.Error); ok {
		ca.signErrorCounter.WithLabelValues(fmt.Sprintf("CFSSL %d", cfErr.ErrorCode)).Inc()
	}
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
					ca.csrExtensionCount.With(prometheus.Labels{csrExtensionCategory: csrExtensionTLSFeature}).Inc()
					value, ok := ext.Value.([]byte)
					if !ok {
						return nil, berrors.MalformedError("malformed extension with OID %v", ext.Type)
					} else if !bytes.Equal(value, mustStapleFeatureValue) {
						ca.csrExtensionCount.With(prometheus.Labels{csrExtensionCategory: csrExtensionTLSFeatureInvalid}).Inc()
						return nil, berrors.MalformedError("unsupported value for extension with OID %v", ext.Type)
					}

					extensions = append(extensions, mustStapleExtension)
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
		ca.csrExtensionCount.With(prometheus.Labels{csrExtensionCategory: csrExtensionBasic}).Inc()
	}

	if hasOther {
		ca.csrExtensionCount.With(prometheus.Labels{csrExtensionCategory: csrExtensionOther}).Inc()
	}

	return extensions, nil
}

var ocspStatusToCode = map[string]int{
	"good":    ocsp.Good,
	"revoked": ocsp.Revoked,
	"unknown": ocsp.Unknown,
}

// GenerateOCSP produces a new OCSP response and returns it
func (ca *CertificateAuthorityImpl) GenerateOCSP(ctx context.Context, req *capb.GenerateOCSPRequest) (*capb.OCSPResponse, error) {
	// req.Status, req.Reason, and req.RevokedAt are often 0, for non-revoked certs.
	// Either CertDER or both (Serial and IssuerID) must be non-zero.
	if core.IsAnyNilOrZero(req, req.CertDER) && core.IsAnyNilOrZero(req, req.Serial, req.IssuerID) {
		return nil, berrors.InternalServerError("Incomplete generate OCSP request")
	}

	var issuer *internalIssuer
	var serial *big.Int
	// Once the feature is enabled we need to support both RPCs that include
	// IssuerID and those that don't as we still need to be able to update rows
	// that didn't have an IssuerID set when they were created. Once this feature
	// has been enabled for a full OCSP lifetime cycle we can remove this
	// functionality.
	if features.Enabled(features.StoreIssuerInfo) && req.IssuerID != nil {
		serialInt, err := core.StringToSerial(*req.Serial)
		if err != nil {
			return nil, err
		}
		serial = serialInt
		var ok bool
		issuer, ok = ca.idToIssuer[*req.IssuerID]
		if !ok {
			return nil, fmt.Errorf("This CA doesn't have an issuer cert with ID %d", *req.IssuerID)
		}
	} else {
		cert, err := x509.ParseCertificate(req.CertDER)
		if err != nil {
			ca.log.AuditErr(err.Error())
			return nil, err
		}

		serial = cert.SerialNumber
		cn := cert.Issuer.CommonName
		issuer = ca.issuers[cn]
		if issuer == nil {
			return nil, fmt.Errorf("This CA doesn't have an issuer cert with CommonName %q", cn)
		}
		err = cert.CheckSignatureFrom(issuer.cert)
		if err != nil {
			return nil, fmt.Errorf("GenerateOCSP was asked to sign OCSP for cert "+
				"%s from %q, but the cert's signature was not valid: %s.",
				core.SerialToString(cert.SerialNumber), cn, err)
		}
	}

	now := ca.clk.Now().Truncate(time.Hour)
	tbsResponse := ocsp.Response{
		Status:       ocspStatusToCode[*req.Status],
		SerialNumber: serial,
		ThisUpdate:   now,
		NextUpdate:   now.Add(ca.ocspLifetime),
	}
	if tbsResponse.Status == ocsp.Revoked {
		tbsResponse.RevokedAt = time.Unix(0, *req.RevokedAt)
		tbsResponse.RevocationReason = int(*req.Reason)
	}

	ocspResponse, err := ocsp.CreateResponse(issuer.cert, issuer.cert, tbsResponse, issuer.ocspSigner)
	ca.noteSignError(err)
	if err == nil {
		ca.signatureCount.With(prometheus.Labels{"purpose": "ocsp"}).Inc()
	}
	return &capb.OCSPResponse{Response: ocspResponse}, err
}

func (ca *CertificateAuthorityImpl) IssuePrecertificate(ctx context.Context, issueReq *capb.IssueCertificateRequest) (*capb.IssuePrecertificateResponse, error) {
	// issueReq.orderID may be zero, for ACMEv1 requests.
	if core.IsAnyNilOrZero(issueReq, issueReq.Csr, issueReq.RegistrationID) {
		return nil, berrors.InternalServerError("Incomplete issue certificate request")
	}

	serialBigInt, validity, err := ca.generateSerialNumberAndValidity()
	if err != nil {
		return nil, err
	}

	regID := *issueReq.RegistrationID

	serialHex := core.SerialToString(serialBigInt)
	nowNanos := ca.clk.Now().UnixNano()
	expiresNanos := validity.NotAfter.UnixNano()
	_, err = ca.sa.AddSerial(ctx, &sapb.AddSerialRequest{
		Serial:  &serialHex,
		RegID:   &regID,
		Created: &nowNanos,
		Expires: &expiresNanos,
	})
	if err != nil {
		return nil, err
	}

	precertDER, err := ca.issuePrecertificateInner(ctx, issueReq, serialBigInt, validity)
	if err != nil {
		return nil, err
	}

	status := string(core.OCSPStatusGood)
	ocspResp, err := ca.GenerateOCSP(ctx, &capb.GenerateOCSPRequest{
		CertDER: precertDER,
		Status:  &status,
	})
	if err != nil {
		err = berrors.InternalServerError(err.Error())
		ca.log.AuditInfof("OCSP Signing failure: serial=[%s] err=[%s]", serialHex, err)
		return nil, err
	}

	req := &sapb.AddCertificateRequest{
		Der:    precertDER,
		RegID:  &regID,
		Ocsp:   ocspResp.Response,
		Issued: &nowNanos,
	}

	// we currently only use one issuer, in the future when we support multiple
	// the issuer will need to be derived from issueReq
	issuerID := idForIssuer(ca.defaultIssuer.cert)
	req.IssuerID = &issuerID

	_, err = ca.sa.AddPrecertificate(ctx, req)
	if err != nil {
		ca.orphanCount.With(prometheus.Labels{"type": "precert"}).Inc()
		err = berrors.InternalServerError(err.Error())
		// Note: This log line is parsed by cmd/orphan-finder. If you make any
		// changes here, you should make sure they are reflected in orphan-finder.
		ca.log.AuditErrf("Failed RPC to store at SA, orphaning precertificate: serial=[%s] cert=[%s] err=[%v], regID=[%d], orderID=[%d]",
			serialHex, hex.EncodeToString(precertDER), err, *issueReq.RegistrationID, *issueReq.OrderID)
		if ca.orphanQueue != nil {
			ca.queueOrphan(&orphanedCert{
				DER:      precertDER,
				RegID:    regID,
				OCSPResp: ocspResp.Response,
				Precert:  true,
			})
		}
		return nil, err
	}

	return &capb.IssuePrecertificateResponse{
		DER: precertDER,
	}, nil
}

// IssueCertificateForPrecertificate takes a precertificate and a set
// of SCTs for that precertificate and uses the signer to create and
// sign a certificate from them. The poison extension is removed and a
// SCT list extension is inserted in its place. Except for this and the
// signature the certificate exactly matches the precertificate. After
// the certificate is signed a OCSP response is generated and the
// response and certificate are stored in the database.
//
// It's critical not to sign two different final certificates for the same
// precertificate. This can happen, for instance, if the caller provides a
// different set of SCTs on subsequent calls to  IssueCertificateForPrecertificate.
// We rely on the RA not to call IssueCertificateForPrecertificate twice for the
// same serial. This is accomplished by the fact that
// IssueCertificateForPrecertificate is only ever called in a straight-through
// RPC path without retries. If there is any error, including a networking
// error, the whole certificate issuance attempt fails and any subsequent
// issuance will use a different serial number.
//
// We also check that the provided serial number does not already exist as a
// final certificate, but this is just a belt-and-suspenders measure, since
// there could be race conditions where two goroutines are issuing for the same
// serial number at the same time.
func (ca *CertificateAuthorityImpl) IssueCertificateForPrecertificate(ctx context.Context, req *capb.IssueCertificateForPrecertificateRequest) (*corepb.Certificate, error) {
	// issueReq.orderID may be zero, for ACMEv1 requests.
	if core.IsAnyNilOrZero(req, req.DER, req.SCTs, req.RegistrationID) {
		return nil, berrors.InternalServerError("Incomplete cert for precertificate request")
	}

	precert, err := x509.ParseCertificate(req.DER)
	if err != nil {
		return nil, err
	}

	serialHex := core.SerialToString(precert.SerialNumber)
	if _, err = ca.sa.GetCertificate(ctx, serialHex); err == nil {
		err = berrors.InternalServerError("issuance of duplicate final certificate requested: %s", serialHex)
		ca.log.AuditErr(err.Error())
		return nil, err
	} else if !berrors.Is(err, berrors.NotFound) {
		return nil, fmt.Errorf("error checking for duplicate issuance of %s: %s", serialHex, err)
	}
	var scts []ct.SignedCertificateTimestamp
	for _, sctBytes := range req.SCTs {
		var sct ct.SignedCertificateTimestamp
		_, err = cttls.Unmarshal(sctBytes, &sct)
		if err != nil {
			return nil, err
		}
		scts = append(scts, sct)
	}
	certPEM, err := ca.defaultIssuer.eeSigner.SignFromPrecert(precert, scts)
	if err != nil {
		return nil, err
	}
	ca.signatureCount.WithLabelValues(string(certType)).Inc()
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		err = berrors.InternalServerError("invalid certificate value returned")
		ca.log.AuditErrf("PEM decode error, aborting: serial=[%s] pem=[%s] err=[%v]", serialHex, certPEM, err)
		return nil, err
	}
	certDER := block.Bytes
	ca.log.AuditInfof("Signing success: serial=[%s] names=[%s] certificate=[%s]",
		serialHex, strings.Join(precert.DNSNames, ", "), hex.EncodeToString(req.DER),
		hex.EncodeToString(certDER))
	err = ca.storeCertificate(ctx, *req.RegistrationID, *req.OrderID, precert.SerialNumber, certDER)
	if err != nil {
		return nil, err
	}
	serialString := core.SerialToString(precert.SerialNumber)
	digest := core.Fingerprint256(certDER)
	issued := precert.NotBefore.UnixNano()
	expires := precert.NotAfter.UnixNano()
	return &corepb.Certificate{
		RegistrationID: req.RegistrationID,
		Serial:         &serialString,
		Der:            certDER,
		Digest:         &digest,
		Issued:         &issued,
		Expires:        &expires,
	}, nil
}

type validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

func (ca *CertificateAuthorityImpl) generateSerialNumberAndValidity() (*big.Int, validity, error) {
	// We want 136 bits of random number, plus an 8-bit instance id prefix.
	const randBits = 136
	serialBytes := make([]byte, randBits/8+1)
	serialBytes[0] = byte(ca.prefix)
	_, err := rand.Read(serialBytes[1:])
	if err != nil {
		err = berrors.InternalServerError("failed to generate serial: %s", err)
		ca.log.AuditErrf("Serial randomness failed, err=[%v]", err)
		return nil, validity{}, err
	}
	serialBigInt := big.NewInt(0)
	serialBigInt = serialBigInt.SetBytes(serialBytes)

	notBefore := ca.clk.Now().Add(-1 * ca.backdate)
	validity := validity{
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(ca.validityPeriod),
	}

	return serialBigInt, validity, nil
}

func (ca *CertificateAuthorityImpl) issuePrecertificateInner(ctx context.Context, issueReq *capb.IssueCertificateRequest, serialBigInt *big.Int, validity validity) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(issueReq.Csr)
	if err != nil {
		return nil, err
	}

	if err := csrlib.VerifyCSR(
		ctx,
		csr,
		ca.maxNames,
		&ca.keyPolicy,
		ca.pa,
		ca.forceCNFromSAN,
		*issueReq.RegistrationID,
	); err != nil {
		ca.log.AuditErr(err.Error())
		// VerifyCSR returns berror instances that can be passed through as-is
		// without wrapping.
		return nil, err
	}

	extensions, err := ca.extensionsFromCSR(csr)
	if err != nil {
		return nil, err
	}

	issuer := ca.defaultIssuer

	if issuer.cert.NotAfter.Before(validity.NotAfter) {
		err = berrors.InternalServerError("cannot issue a certificate that expires after the issuer certificate")
		ca.log.AuditErr(err.Error())
		return nil, err
	}

	// Convert the CSR to PEM
	csrPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	}))

	var profile string
	switch csr.PublicKey.(type) {
	case *rsa.PublicKey:
		profile = ca.rsaProfile
	case *ecdsa.PublicKey:
		profile = ca.ecdsaProfile
	default:
		err = berrors.InternalServerError("unsupported key type %T", csr.PublicKey)
		ca.log.AuditErr(err.Error())
		return nil, err
	}

	// Send the cert off for signing
	req := signer.SignRequest{
		Request: csrPEM,
		Profile: profile,
		Hosts:   csr.DNSNames,
		Subject: &signer.Subject{
			CN: csr.Subject.CommonName,
		},
		Serial:        serialBigInt,
		Extensions:    extensions,
		NotBefore:     validity.NotBefore,
		NotAfter:      validity.NotAfter,
		ReturnPrecert: true,
	}

	serialHex := core.SerialToString(serialBigInt)

	if !ca.forceCNFromSAN {
		req.Subject.SerialNumber = serialHex
	}

	ca.log.AuditInfof("Signing: serial=[%s] names=[%s] csr=[%s]",
		serialHex, strings.Join(csr.DNSNames, ", "), hex.EncodeToString(csr.Raw))

	certPEM, err := issuer.eeSigner.Sign(req)
	ca.noteSignError(err)
	if err != nil {
		// If the Signing error was a pre-issuance lint error then marshal the
		// linting errors to include in the audit err msg.
		if lErr, ok := err.(*local.LintError); ok {
			// NOTE(@cpu): We throw away the JSON marshal error here. If marshaling
			// fails for some reason it's acceptable to log an empty string for the
			// JSON component.
			lintErrsJSON, _ := json.Marshal(lErr.ErrorResults)
			ca.log.AuditErrf("Signing failed: serial=[%s] err=[%v] lintErrors=%s",
				serialHex, err, string(lintErrsJSON))
			return nil, berrors.InternalServerError("failed to sign certificate: %s", err)
		}

		err = berrors.InternalServerError("failed to sign certificate: %s", err)
		ca.log.AuditErrf("Signing failed: serial=[%s] err=[%v]", serialHex, err)
		return nil, err
	}
	ca.signatureCount.WithLabelValues(string(precertType)).Inc()

	if len(certPEM) == 0 {
		err = berrors.InternalServerError("no certificate returned by server")
		ca.log.AuditErrf("PEM empty from Signer: serial=[%s] err=[%v]", serialHex, err)
		return nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		err = berrors.InternalServerError("invalid certificate value returned")
		ca.log.AuditErrf("PEM decode error, aborting: serial=[%s] pem=[%s] err=[%v]", serialHex, certPEM, err)
		return nil, err
	}
	certDER := block.Bytes

	ca.log.AuditInfof("Signing success: serial=[%s] names=[%s] csr=[%s] precertificate=[%s]",
		serialHex, strings.Join(csr.DNSNames, ", "), hex.EncodeToString(csr.Raw),
		hex.EncodeToString(certDER))

	return certDER, nil
}

func (ca *CertificateAuthorityImpl) storeCertificate(
	ctx context.Context,
	regID int64,
	orderID int64,
	serialBigInt *big.Int,
	certDER []byte) error {
	var err error
	now := ca.clk.Now()
	_, err = ca.sa.AddCertificate(ctx, certDER, regID, nil, &now)
	if err != nil {
		ca.orphanCount.With(prometheus.Labels{"type": "cert"}).Inc()
		err = berrors.InternalServerError(err.Error())
		// Note: This log line is parsed by cmd/orphan-finder. If you make any
		// changes here, you should make sure they are reflected in orphan-finder.
		ca.log.AuditErrf("Failed RPC to store at SA, orphaning certificate: serial=[%s] cert=[%s] err=[%v], regID=[%d], orderID=[%d]",
			core.SerialToString(serialBigInt), hex.EncodeToString(certDER), err, regID, orderID)
		if ca.orphanQueue != nil {
			ca.queueOrphan(&orphanedCert{
				DER:   certDER,
				RegID: regID,
			})
		}
		return err
	}
	return nil
}

type orphanedCert struct {
	DER      []byte
	OCSPResp []byte
	RegID    int64
	Precert  bool
}

func (ca *CertificateAuthorityImpl) queueOrphan(o *orphanedCert) {
	if _, err := ca.orphanQueue.EnqueueObject(o); err != nil {
		ca.log.AuditErrf("failed to queue orphan for integration: %s", err)
	}
}

// OrphanIntegrationLoop runs a loop executing integrateOrphans and then waiting a minute.
// It is split out into a separate function called directly by boulder-ca in order to make
// testing the orphan queue functionality somewhat more simple.
func (ca *CertificateAuthorityImpl) OrphanIntegrationLoop() {
	for {
		if err := ca.integrateOrphan(); err != nil {
			if err == goque.ErrEmpty {
				time.Sleep(time.Minute)
				continue
			}
			ca.log.AuditErrf("failed to integrate orphaned certs: %s", err)
			time.Sleep(time.Second)
		}
	}
}

// integrateOrpan removes an orphan from the queue and adds it to the database. The
// item isn't dequeued until it is actually added to the database to prevent items from
// being lost if the CA is restarted between the item being dequeued and being added to
// the database. It calculates the issuance time by subtracting the backdate period from
// the notBefore time.
func (ca *CertificateAuthorityImpl) integrateOrphan() error {
	item, err := ca.orphanQueue.Peek()
	if err != nil {
		if err == goque.ErrEmpty {
			return goque.ErrEmpty
		}
		return fmt.Errorf("failed to peek into orphan queue: %s", err)
	}
	var orphan orphanedCert
	if err = item.ToObject(&orphan); err != nil {
		return fmt.Errorf("failed to marshal orphan: %s", err)
	}
	cert, err := x509.ParseCertificate(orphan.DER)
	if err != nil {
		return fmt.Errorf("failed to parse orphan: %s", err)
	}
	// When calculating the `NotBefore` at issuance time, we subtracted
	// ca.backdate. Now, to calculate the actual issuance time from the NotBefore,
	// we reverse the process and add ca.backdate.
	issued := cert.NotBefore.Add(ca.backdate)
	if orphan.Precert {
		issuedNanos := issued.UnixNano()
		_, err = ca.sa.AddPrecertificate(context.Background(), &sapb.AddCertificateRequest{
			Der:    orphan.DER,
			RegID:  &orphan.RegID,
			Ocsp:   orphan.OCSPResp,
			Issued: &issuedNanos,
		})
		if err != nil && !berrors.Is(err, berrors.Duplicate) {
			return fmt.Errorf("failed to store orphaned precertificate: %s", err)
		}
	} else {
		_, err = ca.sa.AddCertificate(context.Background(), orphan.DER, orphan.RegID, nil, &issued)
		if err != nil && !berrors.Is(err, berrors.Duplicate) {
			return fmt.Errorf("failed to store orphaned certificate: %s", err)
		}
	}
	if _, err = ca.orphanQueue.Dequeue(); err != nil {
		return fmt.Errorf("failed to dequeue integrated orphaned certificate: %s", err)
	}
	typ := "cert"
	if orphan.Precert {
		typ = "precert"
	}
	ca.adoptedOrphanCount.With(prometheus.Labels{"type": typ}).Inc()
	return nil
}
