package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	"github.com/jmhodges/clock"
	"github.com/miekg/pkcs11"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"
	"google.golang.org/protobuf/types/known/timestamppb"

	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	csrlib "github.com/letsencrypt/boulder/csr"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	"github.com/letsencrypt/boulder/issuance"
	"github.com/letsencrypt/boulder/linter"
	blog "github.com/letsencrypt/boulder/log"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

type certificateType string

const (
	precertType = certificateType("precertificate")
	certType    = certificateType("certificate")
)

// Two maps of keys to Issuers. Lookup by PublicKeyAlgorithm is useful for
// determining which issuer to use to sign a given (pre)cert, based on its
// PublicKeyAlgorithm. Lookup by NameID is useful for looking up the appropriate
// issuer based on the issuer of a given (pre)certificate.
type issuerMaps struct {
	byAlg    map[x509.PublicKeyAlgorithm]*issuance.Issuer
	byNameID map[issuance.IssuerNameID]*issuance.Issuer
}

// certificateAuthorityImpl represents a CA that signs certificates.
// It can sign OCSP responses as well, but only via delegation to an ocspImpl.
type certificateAuthorityImpl struct {
	capb.UnimplementedCertificateAuthorityServer
	sa      sapb.StorageAuthorityCertificateClient
	pa      core.PolicyAuthority
	issuers issuerMaps

	// This is temporary, and will be used for testing and slow roll-out
	// of ECDSA issuance, but will then be removed.
	ecdsaAllowList *ECDSAAllowList
	prefix         int // Prepended to the serial number
	validityPeriod time.Duration
	backdate       time.Duration
	maxNames       int
	keyPolicy      goodkey.KeyPolicy
	clk            clock.Clock
	log            blog.Logger
	signatureCount *prometheus.CounterVec
	signErrorCount *prometheus.CounterVec
	lintErrorCount prometheus.Counter
}

// makeIssuerMaps processes a list of issuers into a set of maps, mapping
// nearly-unique identifiers of those issuers to the issuers themselves. Note
// that, if two issuers have the same nearly-unique ID, the *latter* one in
// the input list "wins".
func makeIssuerMaps(issuers []*issuance.Issuer) issuerMaps {
	issuersByAlg := make(map[x509.PublicKeyAlgorithm]*issuance.Issuer, 2)
	issuersByNameID := make(map[issuance.IssuerNameID]*issuance.Issuer, len(issuers))
	for _, issuer := range issuers {
		for _, alg := range issuer.Algs() {
			// TODO(#5259): Enforce that there is only one issuer for each algorithm,
			// instead of taking the first issuer for each algorithm type.
			if issuersByAlg[alg] == nil {
				issuersByAlg[alg] = issuer
			}
		}
		issuersByNameID[issuer.Cert.NameID()] = issuer
	}
	return issuerMaps{issuersByAlg, issuersByNameID}
}

// NewCertificateAuthorityImpl creates a CA instance that can sign certificates
// from any number of issuance.Issuers according to their profiles, and can sign
// OCSP (via delegation to an ocspImpl and its issuers).
func NewCertificateAuthorityImpl(
	sa sapb.StorageAuthorityCertificateClient,
	pa core.PolicyAuthority,
	boulderIssuers []*issuance.Issuer,
	ecdsaAllowList *ECDSAAllowList,
	certExpiry time.Duration,
	certBackdate time.Duration,
	serialPrefix int,
	maxNames int,
	keyPolicy goodkey.KeyPolicy,
	logger blog.Logger,
	stats prometheus.Registerer,
	signatureCount *prometheus.CounterVec,
	signErrorCount *prometheus.CounterVec,
	clk clock.Clock,
) (*certificateAuthorityImpl, error) {
	var ca *certificateAuthorityImpl
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

	if len(boulderIssuers) == 0 {
		return nil, errors.New("must have at least one issuer")
	}

	issuers := makeIssuerMaps(boulderIssuers)

	lintErrorCount := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "lint_errors",
			Help: "Number of issuances that were halted by linting errors",
		})
	stats.MustRegister(lintErrorCount)

	ca = &certificateAuthorityImpl{
		sa:             sa,
		pa:             pa,
		issuers:        issuers,
		validityPeriod: certExpiry,
		backdate:       certBackdate,
		prefix:         serialPrefix,
		maxNames:       maxNames,
		keyPolicy:      keyPolicy,
		log:            logger,
		signatureCount: signatureCount,
		signErrorCount: signErrorCount,
		lintErrorCount: lintErrorCount,
		clk:            clk,
		ecdsaAllowList: ecdsaAllowList,
	}

	return ca, nil
}

// noteSignError is called after operations that may cause a PKCS11 signing error.
func (ca *certificateAuthorityImpl) noteSignError(err error) {
	var pkcs11Error *pkcs11.Error
	if errors.As(err, &pkcs11Error) {
		ca.signErrorCount.WithLabelValues("HSM").Inc()
	}
}

var ocspStatusToCode = map[string]int{
	"good":    ocsp.Good,
	"revoked": ocsp.Revoked,
	"unknown": ocsp.Unknown,
}

func (ca *certificateAuthorityImpl) IssuePrecertificate(ctx context.Context, issueReq *capb.IssueCertificateRequest) (*capb.IssuePrecertificateResponse, error) {
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
	now := ca.clk.Now()
	_, err = ca.sa.AddSerial(ctx, &sapb.AddSerialRequest{
		Serial:    serialHex,
		RegID:     regID,
		CreatedNS: now.UnixNano(),
		Created:   timestamppb.New(now),
		ExpiresNS: validity.NotAfter.UnixNano(),
		Expires:   timestamppb.New(validity.NotAfter),
	})
	if err != nil {
		return nil, err
	}

	precertDER, _, err := ca.issuePrecertificateInner(ctx, issueReq, serialBigInt, validity)
	if err != nil {
		return nil, err
	}

	_, err = ca.sa.SetCertificateStatusReady(ctx, &sapb.Serial{Serial: serialHex})
	if err != nil {
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
func (ca *certificateAuthorityImpl) IssueCertificateForPrecertificate(ctx context.Context, req *capb.IssueCertificateForPrecertificateRequest) (*corepb.Certificate, error) {
	// issueReq.orderID may be zero, for ACMEv1 requests.
	if core.IsAnyNilOrZero(req, req.DER, req.SCTs, req.RegistrationID) {
		return nil, berrors.InternalServerError("Incomplete cert for precertificate request")
	}

	precert, err := x509.ParseCertificate(req.DER)
	if err != nil {
		return nil, err
	}

	serialHex := core.SerialToString(precert.SerialNumber)
	if _, err = ca.sa.GetCertificate(ctx, &sapb.Serial{Serial: serialHex}); err == nil {
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

	names := strings.Join(issuanceReq.DNSNames, ", ")

	ca.log.AuditInfof("Signing cert: serial=[%s] regID=[%d] names=[%s] precert=[%s]",
		serialHex, req.RegistrationID, names, hex.EncodeToString(precert.Raw))

	_, issuanceToken, err := issuer.Prepare(issuanceReq)
	if err != nil {
		ca.log.AuditErrf("Preparing cert failed: serial=[%s] regID=[%d] names=[%s] err=[%v]",
			serialHex, req.RegistrationID, names, err)
		return nil, berrors.InternalServerError("failed to prepare certificate signing: %s", err)
	}

	certDER, err := issuer.Issue(issuanceToken)
	if err != nil {
		ca.noteSignError(err)
		ca.log.AuditErrf("Signing cert failed: serial=[%s] regID=[%d] names=[%s] err=[%v]",
			serialHex, req.RegistrationID, names, err)
		return nil, berrors.InternalServerError("failed to sign certificate: %s", err)
	}

	ca.signatureCount.With(prometheus.Labels{"purpose": string(certType), "issuer": issuer.Name()}).Inc()
	ca.log.AuditInfof("Signing cert success: serial=[%s] regID=[%d] names=[%s] certificate=[%s]",
		serialHex, req.RegistrationID, names, hex.EncodeToString(certDER))

	now := ca.clk.Now()
	_, err = ca.sa.AddCertificate(ctx, &sapb.AddCertificateRequest{
		Der:      certDER,
		RegID:    req.RegistrationID,
		IssuedNS: now.UnixNano(),
		Issued:   timestamppb.New(now),
	})
	if err != nil {
		ca.log.AuditErrf("Failed RPC to store at SA: serial=[%s], cert=[%s], issuerID=[%d], regID=[%d], orderID=[%d], err=[%v]",
			serialHex, hex.EncodeToString(certDER), int64(issuer.Cert.NameID()), req.RegistrationID, req.OrderID, err)
		return nil, err
	}

	return &corepb.Certificate{
		RegistrationID: req.RegistrationID,
		Serial:         core.SerialToString(precert.SerialNumber),
		Der:            certDER,
		Digest:         core.Fingerprint256(certDER),
		IssuedNS:       precert.NotBefore.UnixNano(),
		Issued:         timestamppb.New(precert.NotBefore),
		ExpiresNS:      precert.NotAfter.UnixNano(),
		Expires:        timestamppb.New(precert.NotAfter),
	}, nil
}

type validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

func (ca *certificateAuthorityImpl) generateSerialNumberAndValidity() (*big.Int, validity, error) {
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

	notBefore := ca.clk.Now().Add(-ca.backdate)
	validity := validity{
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(ca.validityPeriod - time.Second),
	}

	return serialBigInt, validity, nil
}

func (ca *certificateAuthorityImpl) issuePrecertificateInner(ctx context.Context, issueReq *capb.IssueCertificateRequest, serialBigInt *big.Int, validity validity) ([]byte, *issuance.Issuer, error) {
	csr, err := x509.ParseCertificateRequest(issueReq.Csr)
	if err != nil {
		return nil, nil, err
	}

	err = csrlib.VerifyCSR(ctx, csr, ca.maxNames, &ca.keyPolicy, ca.pa)
	if err != nil {
		ca.log.AuditErr(err.Error())
		// VerifyCSR returns berror instances that can be passed through as-is
		// without wrapping.
		return nil, nil, err
	}

	var issuer *issuance.Issuer
	var ok bool
	if issueReq.IssuerNameID == 0 {
		// Use the issuer which corresponds to the algorithm of the public key
		// contained in the CSR, unless we have an allowlist of registration IDs
		// for ECDSA, in which case switch all not-allowed accounts to RSA issuance.
		alg := csr.PublicKeyAlgorithm
		if alg == x509.ECDSA && !features.Enabled(features.ECDSAForAll) && ca.ecdsaAllowList != nil && !ca.ecdsaAllowList.permitted(issueReq.RegistrationID) {
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

	if issuer.Cert.NotAfter.Before(validity.NotAfter) {
		err = berrors.InternalServerError("cannot issue a certificate that expires after the issuer certificate")
		ca.log.AuditErr(err.Error())
		return nil, nil, err
	}

	serialHex := core.SerialToString(serialBigInt)

	ca.log.AuditInfof("Signing precert: serial=[%s] regID=[%d] names=[%s] csr=[%s]",
		serialHex, issueReq.RegistrationID, strings.Join(csr.DNSNames, ", "), hex.EncodeToString(csr.Raw))

	names := csrlib.NamesFromCSR(csr)
	req := &issuance.IssuanceRequest{
		PublicKey:         csr.PublicKey,
		Serial:            serialBigInt.Bytes(),
		DNSNames:          names.SANs,
		CommonName:        names.CN,
		IncludeCTPoison:   true,
		IncludeMustStaple: issuance.ContainsMustStaple(csr.Extensions),
		NotBefore:         validity.NotBefore,
		NotAfter:          validity.NotAfter,
	}

	lintCertBytes, issuanceToken, err := issuer.Prepare(req)
	if err != nil {
		ca.log.AuditErrf("Preparing precert failed: serial=[%s] regID=[%d] names=[%s] err=[%v]",
			serialHex, issueReq.RegistrationID, strings.Join(csr.DNSNames, ", "), err)
		if errors.Is(err, linter.ErrLinting) {
			ca.lintErrorCount.Inc()
		}
		return nil, nil, berrors.InternalServerError("failed to prepare precertificate signing: %s", err)
	}

	now := ca.clk.Now()
	_, err = ca.sa.AddPrecertificate(context.Background(), &sapb.AddCertificateRequest{
		Der:          lintCertBytes,
		RegID:        issueReq.RegistrationID,
		IssuedNS:     now.UnixNano(),
		Issued:       timestamppb.New(now),
		IssuerNameID: int64(issuer.Cert.NameID()),
		OcspNotReady: true,
	})
	if err != nil {
		return nil, nil, err
	}

	certDER, err := issuer.Issue(issuanceToken)
	if err != nil {
		ca.noteSignError(err)
		ca.log.AuditErrf("Signing precert failed: serial=[%s] regID=[%d] names=[%s] err=[%v]",
			serialHex, issueReq.RegistrationID, strings.Join(csr.DNSNames, ", "), err)
		return nil, nil, berrors.InternalServerError("failed to sign precertificate: %s", err)
	}

	ca.signatureCount.With(prometheus.Labels{"purpose": string(precertType), "issuer": issuer.Name()}).Inc()
	ca.log.AuditInfof("Signing precert success: serial=[%s] regID=[%d] names=[%s] precertificate=[%s]",
		serialHex, issueReq.RegistrationID, strings.Join(csr.DNSNames, ", "), hex.EncodeToString(certDER))

	return certDER, issuer, nil
}
