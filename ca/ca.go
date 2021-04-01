package ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/beeker1121/goque"
	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	"github.com/jmhodges/clock"
	"github.com/miekg/pkcs11"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"

	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	csrlib "github.com/letsencrypt/boulder/csr"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	sapb "github.com/letsencrypt/boulder/sa/proto"
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

// Four maps of keys to internalIssuers. Lookup by PublicKeyAlgorithm is
// useful for determining which issuer to use to sign a given (pre)cert, based
// on its PublicKeyAlgorithm. Lookup by CommonName is useful for determining
// which issuer to use to sign an OCSP response, based on the cert's
// Issuer CN. Lookup by ID is useful for the same functionality, in cases
// where features.StoreIssuerInfo is true and the OCSP request is identified
// by Serial and IssuerID rather than by the full cert. Lookup by NameID is
// useful as a easier-to-compute replacement for both byName and byID lookups.
type issuerMaps struct {
	byAlg    map[x509.PublicKeyAlgorithm]*internalIssuer
	byName   map[string]*internalIssuer
	byID     map[issuance.IssuerID]*internalIssuer
	byNameID map[issuance.IssuerNameID]*internalIssuer
}

// CertificateAuthorityImpl represents a CA that signs certificates, CRLs, and
// OCSP responses.
type CertificateAuthorityImpl struct {
	sa                 certificateStorage
	pa                 core.PolicyAuthority
	issuers            issuerMaps
	ecdsaAllowedRegIDs map[int64]bool
	prefix             int // Prepended to the serial number
	validityPeriod     time.Duration
	backdate           time.Duration
	maxNames           int
	ocspLifetime       time.Duration
	keyPolicy          goodkey.KeyPolicy
	orphanQueue        *goque.Queue
	ocspLogQueue       *ocspLogQueue
	clk                clock.Clock
	log                blog.Logger
	signatureCount     *prometheus.CounterVec
	csrExtensionCount  *prometheus.CounterVec
	orphanCount        *prometheus.CounterVec
	adoptedOrphanCount *prometheus.CounterVec
	signErrorCounter   *prometheus.CounterVec
}

// Issuer represents a single issuer certificate, along with its key.
type Issuer struct {
	Signer crypto.Signer
	Cert   *issuance.Certificate
}

// internalIssuer represents the fully initialized internal state for a single
// issuer, including the OCSP signer object.
// TODO(#5086): Remove the ocsp-specific pieces of this as we factor OCSP out.
type internalIssuer struct {
	cert          *issuance.Certificate
	ocspSigner    crypto.Signer
	boulderIssuer *issuance.Issuer
}

func makeInternalIssuers(issuers []*issuance.Issuer, lifespanOCSP time.Duration) (issuerMaps, error) {
	issuersByAlg := make(map[x509.PublicKeyAlgorithm]*internalIssuer, 2)
	issuersByName := make(map[string]*internalIssuer, len(issuers))
	issuersByID := make(map[issuance.IssuerID]*internalIssuer, len(issuers))
	issuersByNameID := make(map[issuance.IssuerNameID]*internalIssuer, len(issuers))
	for _, issuer := range issuers {
		ii := &internalIssuer{
			cert:          issuer.Cert,
			ocspSigner:    issuer.Signer,
			boulderIssuer: issuer,
		}
		for _, alg := range issuer.Algs() {
			// TODO(#5259): Enforce that there is only one issuer for each algorithm,
			// instead of taking the first issuer for each algorithm type.
			if issuersByAlg[alg] == nil {
				issuersByAlg[alg] = ii
			}
		}
		if issuersByName[issuer.Name()] != nil {
			return issuerMaps{}, errors.New("Multiple issuer certs with the same CommonName are not supported")
		}
		issuersByName[issuer.Name()] = ii
		issuersByID[issuer.ID()] = ii
		issuersByNameID[issuer.Cert.NameID()] = ii
	}
	return issuerMaps{issuersByAlg, issuersByName, issuersByID, issuersByNameID}, nil
}

// NewCertificateAuthorityImpl creates a CA instance that can sign certificates
// from a single issuer (the first first in the issuers slice), and can sign OCSP
// for any of the issuer certificates provided.
func NewCertificateAuthorityImpl(
	sa certificateStorage,
	pa core.PolicyAuthority,
	boulderIssuers []*issuance.Issuer,
	ecdsaAllowedRegIDs []int64,
	certExpiry time.Duration,
	certBackdate time.Duration,
	serialPrefix int,
	maxNames int,
	ocspLifetime time.Duration,
	keyPolicy goodkey.KeyPolicy,
	orphanQueue *goque.Queue,
	ocspLogMaxLength int,
	ocspLogPeriod time.Duration,
	logger blog.Logger,
	stats prometheus.Registerer,
	clk clock.Clock,
) (*CertificateAuthorityImpl, error) {
	var ca *CertificateAuthorityImpl
	var err error

	// TODO(briansmith): Make the backdate setting mandatory after the
	// production ca.json has been updated to include it. Until then, manually
	// default to 1h, which is the backdating duration we currently use.
	if certBackdate == 0 {
		certBackdate = time.Hour
	}

	if serialPrefix <= 0 || serialPrefix >= 256 {
		err = errors.New("Must have a positive non-zero serial prefix less than 256 for CA.")
		return nil, err
	}
	issuers, err := makeInternalIssuers(boulderIssuers, ocspLifetime)
	if err != nil {
		return nil, err
	}

	ecdsaAllowedRegIDsMap := make(map[int64]bool, len(ecdsaAllowedRegIDs))
	for _, regID := range ecdsaAllowedRegIDs {
		ecdsaAllowedRegIDsMap[regID] = true
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
		[]string{"purpose", "issuer"})
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

	var ocspLogQueue *ocspLogQueue
	if ocspLogMaxLength > 0 {
		ocspLogQueue = newOCSPLogQueue(ocspLogMaxLength, ocspLogPeriod, stats, logger)
	}

	ca = &CertificateAuthorityImpl{
		sa:                 sa,
		pa:                 pa,
		issuers:            issuers,
		ecdsaAllowedRegIDs: ecdsaAllowedRegIDsMap,
		validityPeriod:     certExpiry,
		backdate:           certBackdate,
		prefix:             serialPrefix,
		maxNames:           maxNames,
		ocspLifetime:       ocspLifetime,
		keyPolicy:          keyPolicy,
		orphanQueue:        orphanQueue,
		ocspLogQueue:       ocspLogQueue,
		log:                logger,
		signatureCount:     signatureCount,
		csrExtensionCount:  csrExtensionCount,
		orphanCount:        orphanCount,
		adoptedOrphanCount: adoptedOrphanCount,
		signErrorCounter:   signErrorCounter,
		clk:                clk,
	}

	return ca, nil
}

// noteSignError is called after operations that may cause a PKCS11 signing error.
func (ca *CertificateAuthorityImpl) noteSignError(err error) {
	var pkcs11Error *pkcs11.Error
	if errors.As(err, &pkcs11Error) {
		ca.signErrorCounter.WithLabelValues("HSM").Inc()
	}
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
	if features.Enabled(features.StoreIssuerInfo) && req.IssuerID != 0 {
		serialInt, err := core.StringToSerial(req.Serial)
		if err != nil {
			return nil, err
		}
		serial = serialInt
		var ok bool
		issuer, ok = ca.issuers.byID[issuance.IssuerID(req.IssuerID)]
		if !ok {
			return nil, fmt.Errorf("This CA doesn't have an issuer cert with ID %d", req.IssuerID)
		}
	} else {
		cert, err := x509.ParseCertificate(req.CertDER)
		if err != nil {
			err := fmt.Errorf("parsing certificate for GenerateOCSP: %w", err)
			ca.log.AuditErr(err.Error())
			return nil, err
		}

		serial = cert.SerialNumber
		cn := cert.Issuer.CommonName
		issuer = ca.issuers.byName[cn]
		if issuer == nil {
			return nil, fmt.Errorf("This CA doesn't have an issuer cert with CommonName %q", cn)
		}
		err = cert.CheckSignatureFrom(issuer.cert.Certificate)
		if err != nil {
			return nil, fmt.Errorf("GenerateOCSP was asked to sign OCSP for cert "+
				"%s from %q, but the cert's signature was not valid: %s.",
				core.SerialToString(cert.SerialNumber), cn, err)
		}
	}

	now := ca.clk.Now().Truncate(time.Hour)
	tbsResponse := ocsp.Response{
		Status:       ocspStatusToCode[req.Status],
		SerialNumber: serial,
		ThisUpdate:   now,
		NextUpdate:   now.Add(ca.ocspLifetime),
	}
	if tbsResponse.Status == ocsp.Revoked {
		tbsResponse.RevokedAt = time.Unix(0, req.RevokedAt)
		tbsResponse.RevocationReason = int(req.Reason)
	}

	if ca.ocspLogQueue != nil {
		ca.ocspLogQueue.enqueue(serial.Bytes(), now, ocsp.ResponseStatus(tbsResponse.Status))
	}

	ocspResponse, err := ocsp.CreateResponse(issuer.cert.Certificate, issuer.cert.Certificate, tbsResponse, issuer.ocspSigner)
	ca.noteSignError(err)
	if err == nil {
		ca.signatureCount.With(prometheus.Labels{"purpose": "ocsp", "issuer": issuer.boulderIssuer.Name()}).Inc()
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

	serialHex := core.SerialToString(serialBigInt)
	regID := issueReq.RegistrationID
	nowNanos := ca.clk.Now().UnixNano()
	expiresNanos := validity.NotAfter.UnixNano()
	_, err = ca.sa.AddSerial(ctx, &sapb.AddSerialRequest{
		Serial:  serialHex,
		RegID:   regID,
		Created: nowNanos,
		Expires: expiresNanos,
	})
	if err != nil {
		return nil, err
	}

	precertDER, issuer, err := ca.issuePrecertificateInner(ctx, issueReq, serialBigInt, validity)
	if err != nil {
		return nil, err
	}

	ocspResp, err := ca.GenerateOCSP(ctx, &capb.GenerateOCSPRequest{
		CertDER: precertDER,
		Status:  string(core.OCSPStatusGood),
	})
	if err != nil {
		err = berrors.InternalServerError(err.Error())
		ca.log.AuditInfof("OCSP Signing failure: serial=[%s] err=[%s]", serialHex, err)
		return nil, err
	}

	issuerID := issuer.cert.ID()

	req := &sapb.AddCertificateRequest{
		Der:      precertDER,
		RegID:    regID,
		Ocsp:     ocspResp.Response,
		Issued:   nowNanos,
		IssuerID: int64(issuerID),
	}

	_, err = ca.sa.AddPrecertificate(ctx, req)
	if err != nil {
		ca.orphanCount.With(prometheus.Labels{"type": "precert"}).Inc()
		err = berrors.InternalServerError(err.Error())
		// Note: This log line is parsed by cmd/orphan-finder. If you make any
		// changes here, you should make sure they are reflected in orphan-finder.
		ca.log.AuditErrf("Failed RPC to store at SA, orphaning precertificate: serial=[%s], cert=[%s], issuerID=[%d], regID=[%d], orderID=[%d], err=[%v]",
			serialHex, hex.EncodeToString(precertDER), issuerID, issueReq.RegistrationID, issueReq.OrderID, err)
		if ca.orphanQueue != nil {
			ca.queueOrphan(&orphanedCert{
				DER:      precertDER,
				RegID:    regID,
				OCSPResp: ocspResp.Response,
				Precert:  true,
				IssuerID: int64(issuerID),
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
	} else if !errors.Is(err, berrors.NotFound) {
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

	issuer, ok := ca.issuers.byNameID[issuance.GetIssuerNameID(precert)]
	if !ok {
		return nil, berrors.InternalServerError("no issuer found for Issuer Name %s", precert.Issuer)
	}

	issuanceReq, err := issuance.RequestFromPrecert(precert, scts)
	if err != nil {
		return nil, err
	}
	certDER, err := issuer.boulderIssuer.Issue(issuanceReq)
	if err != nil {
		return nil, err
	}
	ca.signatureCount.With(prometheus.Labels{"purpose": string(certType), "issuer": issuer.boulderIssuer.Name()}).Inc()
	ca.log.AuditInfof("Signing success: serial=[%s] names=[%s] csr=[%s] certificate=[%s]",
		serialHex, strings.Join(precert.DNSNames, ", "), hex.EncodeToString(req.DER),
		hex.EncodeToString(certDER))
	err = ca.storeCertificate(ctx, req.RegistrationID, req.OrderID, precert.SerialNumber, certDER, int64(issuer.cert.ID()))
	if err != nil {
		return nil, err
	}
	return &corepb.Certificate{
		RegistrationID: req.RegistrationID,
		Serial:         core.SerialToString(precert.SerialNumber),
		Der:            certDER,
		Digest:         core.Fingerprint256(certDER),
		Issued:         precert.NotBefore.UnixNano(),
		Expires:        precert.NotAfter.UnixNano(),
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

func (ca *CertificateAuthorityImpl) issuePrecertificateInner(ctx context.Context, issueReq *capb.IssueCertificateRequest, serialBigInt *big.Int, validity validity) ([]byte, *internalIssuer, error) {
	csr, err := x509.ParseCertificateRequest(issueReq.Csr)
	if err != nil {
		return nil, nil, err
	}

	if err := csrlib.VerifyCSR(
		ctx,
		csr,
		ca.maxNames,
		&ca.keyPolicy,
		ca.pa,
		issueReq.RegistrationID,
	); err != nil {
		ca.log.AuditErr(err.Error())
		// VerifyCSR returns berror instances that can be passed through as-is
		// without wrapping.
		return nil, nil, err
	}

	var issuer *internalIssuer
	var ok bool
	if issueReq.IssuerNameID == 0 {
		// Use the issuer which corresponds to the algorithm of the public key
		// contained in the CSR, unless we have an allowlist of registration IDs
		// for ECDSA, in which case switch all not-allowed accounts to RSA issuance.
		alg := csr.PublicKeyAlgorithm
		if alg == x509.ECDSA && !features.Enabled(features.ECDSAForAll) && !ca.ecdsaAllowedRegIDs[issueReq.RegistrationID] {
			alg = x509.RSA
		}
		issuer, ok = ca.issuers.byAlg[alg]
		if !ok {
			return nil, nil, berrors.InternalServerError("no issuer found for public key algorithm %s", csr.PublicKeyAlgorithm)
		}
	} else {
		issuer, ok = ca.issuers.byNameID[issuance.IssuerNameID(issueReq.IssuerNameID)]
		if !ok {
			return nil, nil, berrors.InternalServerError("no issuer found for IssuerNameID %d", issueReq.IssuerNameID)
		}
	}

	if issuer.cert.NotAfter.Before(validity.NotAfter) {
		err = berrors.InternalServerError("cannot issue a certificate that expires after the issuer certificate")
		ca.log.AuditErr(err.Error())
		return nil, nil, err
	}

	serialHex := core.SerialToString(serialBigInt)

	ca.log.AuditInfof("Signing: serial=[%s] names=[%s] csr=[%s]",
		serialHex, strings.Join(csr.DNSNames, ", "), hex.EncodeToString(csr.Raw))
	certDER, err := issuer.boulderIssuer.Issue(&issuance.IssuanceRequest{
		PublicKey:         csr.PublicKey,
		Serial:            serialBigInt.Bytes(),
		CommonName:        csr.Subject.CommonName,
		DNSNames:          csr.DNSNames,
		IncludeCTPoison:   true,
		IncludeMustStaple: issuance.ContainsMustStaple(csr.Extensions),
		NotBefore:         validity.NotBefore,
		NotAfter:          validity.NotAfter,
	})
	ca.noteSignError(err)
	if err != nil {
		err = berrors.InternalServerError("failed to sign certificate: %s", err)
		ca.log.AuditErrf("Signing failed: serial=[%s] err=[%v]", serialHex, err)
		return nil, nil, err
	}
	ca.signatureCount.With(prometheus.Labels{"purpose": string(precertType), "issuer": issuer.boulderIssuer.Name()}).Inc()

	ca.log.AuditInfof("Signing success: serial=[%s] names=[%s] csr=[%s] precertificate=[%s]",
		serialHex, strings.Join(csr.DNSNames, ", "), hex.EncodeToString(csr.Raw),
		hex.EncodeToString(certDER))

	return certDER, issuer, nil
}

func (ca *CertificateAuthorityImpl) storeCertificate(
	ctx context.Context,
	regID int64,
	orderID int64,
	serialBigInt *big.Int,
	certDER []byte,
	issuerID int64) error {
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
				DER:      certDER,
				RegID:    regID,
				IssuerID: issuerID,
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
	IssuerID int64
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

// LogOCSPLoop collects OCSP generation log events into bundles, and logs
// them periodically.
func (ca *CertificateAuthorityImpl) LogOCSPLoop() {
	if ca.ocspLogQueue != nil {
		ca.ocspLogQueue.loop()
	}
}

// Stop asks this CertificateAuthorityImpl to shut down. It must be called
// after the corresponding RPC service is shut down and there are no longer
// any inflight RPCs. It will attempt to drain any logging queues (which may
// block), and will return only when done.
func (ca *CertificateAuthorityImpl) Stop() {
	if ca.ocspLogQueue != nil {
		ca.ocspLogQueue.stop()
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
			Der:      orphan.DER,
			RegID:    orphan.RegID,
			Ocsp:     orphan.OCSPResp,
			Issued:   issuedNanos,
			IssuerID: orphan.IssuerID,
		})
		if err != nil && !errors.Is(err, berrors.Duplicate) {
			return fmt.Errorf("failed to store orphaned precertificate: %s", err)
		}
	} else {
		_, err = ca.sa.AddCertificate(context.Background(), orphan.DER, orphan.RegID, nil, &issued)
		if err != nil && !errors.Is(err, berrors.Duplicate) {
			return fmt.Errorf("failed to store orphaned certificate: %s", err)
		}
	}
	if _, err = ca.orphanQueue.Dequeue(); err != nil {
		return fmt.Errorf("failed to dequeue integrated orphaned certificate: %s", err)
	}
	ca.log.AuditInfof("Incorporated orphaned certificate: serial=[%s] cert=[%s] regID=[%d]",
		core.SerialToString(cert.SerialNumber), hex.EncodeToString(orphan.DER), orphan.RegID)
	typ := "cert"
	if orphan.Precert {
		typ = "precert"
	}
	ca.adoptedOrphanCount.With(prometheus.Labels{"type": typ}).Inc()
	return nil
}
