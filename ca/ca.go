package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	mrand "math/rand/v2"
	"slices"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	"github.com/jmhodges/clock"
	"github.com/miekg/pkcs11"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
	"google.golang.org/protobuf/types/known/timestamppb"

	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/core"
	csrlib "github.com/letsencrypt/boulder/csr"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/goodkey"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/issuance"
	"github.com/letsencrypt/boulder/linter"
	blog "github.com/letsencrypt/boulder/log"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

type certificateType string

const (
	precertType = certificateType("precertificate")
	certType    = certificateType("certificate")
)

// issuanceEvent is logged before and after issuance of precertificates and certificates.
// The `omitempty` fields are not always present.
// CSR, Precertificate, and Certificate are hex-encoded DER bytes to make it easier to
// ad-hoc search for sequences or OIDs in logs. Other data, like public key within CSR,
// is logged as base64 because it doesn't have interesting DER structure.
type issuanceEvent struct {
	Requester       int64
	OrderID         int64
	Profile         string
	Issuer          string
	IssuanceRequest *issuance.IssuanceRequest
	CSR             string `json:",omitempty"`
	Result          issuanceEventResult
}

// issuanceEventResult exists just to lend some extra structure to the
// issuanceEvent struct above.
type issuanceEventResult struct {
	Precertificate string `json:",omitempty"`
	Certificate    string `json:",omitempty"`
}

// caMetrics holds various metrics which are shared between caImpl and crlImpl.
type caMetrics struct {
	signatureCount *prometheus.CounterVec
	signErrorCount *prometheus.CounterVec
	lintErrorCount prometheus.Counter
	certificates   *prometheus.CounterVec
}

func NewCAMetrics(stats prometheus.Registerer) *caMetrics {
	signatureCount := promauto.With(stats).NewCounterVec(prometheus.CounterOpts{
		Name: "signatures",
		Help: "Number of signatures",
	}, []string{"purpose", "issuer"})

	signErrorCount := promauto.With(stats).NewCounterVec(prometheus.CounterOpts{
		Name: "signature_errors",
		Help: "A counter of signature errors labelled by error type",
	}, []string{"type"})

	lintErrorCount := promauto.With(stats).NewCounter(prometheus.CounterOpts{
		Name: "lint_errors",
		Help: "Number of issuances that were halted by linting errors",
	})

	certificates := promauto.With(stats).NewCounterVec(prometheus.CounterOpts{
		Name: "certificates",
		Help: "Number of certificates issued",
	}, []string{"profile"})

	return &caMetrics{signatureCount, signErrorCount, lintErrorCount, certificates}
}

func (m *caMetrics) noteSignError(err error) {
	var pkcs11Error pkcs11.Error
	if errors.As(err, &pkcs11Error) {
		m.signErrorCount.WithLabelValues("HSM").Inc()
	}
}

// certificateAuthorityImpl represents a CA that signs certificates.
type certificateAuthorityImpl struct {
	capb.UnsafeCertificateAuthorityServer
	sa        sapb.StorageAuthorityCertificateClient
	sctClient rapb.SCTProviderClient
	pa        core.PolicyAuthority
	issuers   []*issuance.Issuer
	profiles  map[string]*issuance.Profile

	// The prefix is prepended to the serial number.
	prefix    byte
	maxNames  int
	keyPolicy goodkey.KeyPolicy
	clk       clock.Clock
	log       blog.Logger
	metrics   *caMetrics
	tracer    trace.Tracer
}

var _ capb.CertificateAuthorityServer = (*certificateAuthorityImpl)(nil)

// NewCertificateAuthorityImpl creates a CA instance that can sign certificates
// from any number of issuance.Issuers and for any number of profiles.
func NewCertificateAuthorityImpl(
	sa sapb.StorageAuthorityCertificateClient,
	sctService rapb.SCTProviderClient,
	pa core.PolicyAuthority,
	issuers []*issuance.Issuer,
	profiles map[string]*issuance.Profile,
	serialPrefix byte,
	maxNames int,
	keyPolicy goodkey.KeyPolicy,
	logger blog.Logger,
	metrics *caMetrics,
	clk clock.Clock,
) (*certificateAuthorityImpl, error) {
	if serialPrefix < 0x01 || serialPrefix > 0x7f {
		return nil, errors.New("serial prefix must be between 0x01 (1) and 0x7f (127)")
	}

	if len(issuers) == 0 {
		return nil, errors.New("must have at least one issuer")
	}

	if len(profiles) == 0 {
		return nil, errors.New("must have at least one certificate profile")
	}

	issuableKeys := make(map[x509.PublicKeyAlgorithm]bool)
	issuableProfiles := make(map[string]bool)
	for _, issuer := range issuers {
		if issuer.IsActive() && len(issuer.Profiles()) == 0 {
			return nil, fmt.Errorf("issuer %q is active but has no profiles", issuer.Name())
		}

		for _, profile := range issuer.Profiles() {
			_, ok := profiles[profile]
			if !ok {
				return nil, fmt.Errorf("issuer %q lists profile %q, which is not configured", issuer.Name(), profile)
			}
			issuableProfiles[profile] = true
		}

		issuableKeys[issuer.KeyType()] = true
	}

	for profile := range profiles {
		if !issuableProfiles[profile] {
			return nil, fmt.Errorf("profile %q configured, but no issuer lists it", profile)
		}
	}

	for _, keyAlg := range []x509.PublicKeyAlgorithm{x509.ECDSA, x509.RSA} {
		if !issuableKeys[keyAlg] {
			return nil, fmt.Errorf("no %s issuers configured", keyAlg)
		}
	}

	return &certificateAuthorityImpl{
		sa:        sa,
		sctClient: sctService,
		pa:        pa,
		issuers:   issuers,
		profiles:  profiles,
		prefix:    serialPrefix,
		maxNames:  maxNames,
		keyPolicy: keyPolicy,
		log:       logger,
		metrics:   metrics,
		tracer:    otel.GetTracerProvider().Tracer("github.com/letsencrypt/boulder/ca"),
		clk:       clk,
	}, nil
}

// IssueCertificate is the gRPC handler responsible for the entire [issuance
// cycle]. It takes as input just a CSR and a profile name. It generates the
// unique serial number locally, and uses the profile and the CA's clock to
// generate the validity period. It writes the serial to the database to prevent
// duplicate use of serials, generates and stores the *linting* precertificate
// as a record of what we intended to issue, contacts the SCTService (currently
// an RA instance) to retrieve SCTs, and finally generates and saves the final
// certificate.
//
// [issuance cycle]:
// https://github.com/letsencrypt/boulder/blob/main/docs/ISSUANCE-CYCLE.md
func (ca *certificateAuthorityImpl) IssueCertificate(ctx context.Context, req *capb.IssueCertificateRequest) (*capb.IssueCertificateResponse, error) {
	// Step 1: Locally process the gRPC request and its embedded CSR to extract
	// the relevant information, like the pubkey and SANs. Also generate
	// some metadata from scratch, such as the serial and validity period.
	if core.IsAnyNilOrZero(req, req.RegistrationID, req.OrderID, req.CertProfileName, req.Csr) {
		return nil, berrors.InternalServerError("Incomplete issue certificate request")
	}

	if ca.sctClient == nil {
		return nil, errors.New("IssueCertificate called with a nil SCT service")
	}

	profile, ok := ca.profiles[req.CertProfileName]
	if !ok {
		return nil, fmt.Errorf("incapable of using a profile named %q", req.CertProfileName)
	}

	notBefore, notAfter := profile.GenerateValidity(ca.clk.Now())

	csr, err := x509.ParseCertificateRequest(req.Csr)
	if err != nil {
		return nil, err
	}

	err = csrlib.VerifyCSR(ctx, csr, ca.maxNames, &ca.keyPolicy, ca.pa)
	if err != nil {
		return nil, err
	}

	issuer, err := ca.pickIssuer(req.CertProfileName, csr.PublicKeyAlgorithm)
	if err != nil {
		return nil, err
	}

	if issuer.Cert.NotAfter.Before(notAfter) {
		err = berrors.InternalServerError("cannot issue a certificate that expires after the issuer certificate")
		ca.log.AuditErr(err.Error())
		return nil, err
	}

	subjectKeyId, err := generateSKID(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("computing subject key ID: %w", err)
	}

	dnsNames, ipAddresses, err := identifier.FromCSR(csr).ToValues()
	if err != nil {
		return nil, err
	}

	var ipStrings []string
	for _, ip := range csr.IPAddresses {
		ipStrings = append(ipStrings, ip.String())
	}

	serialBigInt, err := ca.generateSerialNumber()
	if err != nil {
		return nil, err
	}
	serialHex := core.SerialToString(serialBigInt)

	// Step 2: Persist the serial and minimal metadata, to ensure that we never
	// duplicate a serial.
	_, err = ca.sa.AddSerial(ctx, &sapb.AddSerialRequest{
		Serial:  serialHex,
		RegID:   req.RegistrationID,
		Created: timestamppb.New(ca.clk.Now()),
		Expires: timestamppb.New(notAfter),
	})
	if err != nil {
		return nil, fmt.Errorf("persisting serial to database: %w", err)
	}

	// Step 3: Issue the linting precert, persist it to the database, and then
	// issue the real precert.
	precertReq := &issuance.IssuanceRequest{
		PublicKey:       issuance.MarshalablePublicKey{PublicKey: csr.PublicKey},
		SubjectKeyId:    subjectKeyId,
		Serial:          serialBigInt.Bytes(),
		NotBefore:       notBefore,
		NotAfter:        notAfter,
		CommonName:      csrlib.CNFromCSR(csr),
		DNSNames:        dnsNames,
		IPAddresses:     ipAddresses,
		IncludeCTPoison: true,
	}

	_, span := ca.tracer.Start(ctx, "issuance", trace.WithAttributes(
		attribute.String("serial", serialHex),
		attribute.String("issuer", issuer.Name()),
		attribute.String("certProfileName", req.CertProfileName),
		attribute.StringSlice("names", csr.DNSNames),
		attribute.StringSlice("ipAddresses", ipStrings),
	))
	defer span.End()

	lintPrecertDER, issuanceToken, err := issuer.Prepare(profile, precertReq)
	if err != nil {
		ca.log.AuditErrf("Preparing precert failed: serial=[%s] err=[%v]", serialHex, err)
		if errors.Is(err, linter.ErrLinting) {
			ca.metrics.lintErrorCount.Inc()
		}
		return nil, fmt.Errorf("failed to prepare precertificate signing: %w", err)
	}

	// Note: we write the linting certificate bytes to this table, rather than the precertificate
	// (which we audit log but do not put in the database). This is to ensure that even if there is
	// an error immediately after signing the precertificate, we have a record in the DB of what we
	// intended to sign, and can do revocations based on that. See #6807.
	// The name of the SA method ("AddPrecertificate") is a historical artifact.
	_, err = ca.sa.AddPrecertificate(context.Background(), &sapb.AddCertificateRequest{
		Der:          lintPrecertDER,
		RegID:        req.RegistrationID,
		Issued:       timestamppb.New(ca.clk.Now()),
		IssuerNameID: int64(issuer.NameID()),
	})
	if err != nil {
		return nil, fmt.Errorf("persisting linting precert to database: %w", err)
	}

	ca.log.AuditObject("Signing precert", issuanceEvent{
		Requester:       req.RegistrationID,
		OrderID:         req.OrderID,
		Profile:         req.CertProfileName,
		Issuer:          issuer.Name(),
		IssuanceRequest: precertReq,
		CSR:             hex.EncodeToString(csr.Raw),
	})

	precertDER, err := issuer.Issue(issuanceToken)
	if err != nil {
		ca.metrics.noteSignError(err)
		ca.log.AuditErrf("Signing precert failed: serial=[%s] err=[%v]", serialHex, err)
		return nil, fmt.Errorf("failed to sign precertificate: %w", err)
	}
	ca.metrics.signatureCount.With(prometheus.Labels{"purpose": string(precertType), "issuer": issuer.Name()}).Inc()

	ca.log.AuditObject("Signing precert success", issuanceEvent{
		Requester:       req.RegistrationID,
		OrderID:         req.OrderID,
		Profile:         req.CertProfileName,
		Issuer:          issuer.Name(),
		IssuanceRequest: precertReq,
		Result:          issuanceEventResult{Precertificate: hex.EncodeToString(precertDER)},
	})

	err = tbsCertIsDeterministic(lintPrecertDER, precertDER)
	if err != nil {
		return nil, err
	}

	precert, err := x509.ParseCertificate(precertDER)
	if err != nil {
		return nil, fmt.Errorf("parsing precertificate: %w", err)
	}

	// Step 4: Get SCTs for inclusion in the final certificate.
	sctResp, err := ca.sctClient.GetSCTs(ctx, &rapb.SCTRequest{PrecertDER: precertDER})
	if err != nil {
		return nil, fmt.Errorf("getting SCTs: %w", err)
	}

	var scts []ct.SignedCertificateTimestamp
	for _, singleSCTBytes := range sctResp.SctDER {
		var sct ct.SignedCertificateTimestamp
		_, err = cttls.Unmarshal(singleSCTBytes, &sct)
		if err != nil {
			return nil, err
		}
		scts = append(scts, sct)
	}

	// Step 5: Issue and save the final certificate.
	//
	// Given a precertificate, a set of SCTs for that precertificate, and the same
	// issuer and profile which were used to generate that precert, generate a
	// linting final certificate, then sign a final certificate using a real
	// issuer. The poison extension is removed from the precertificate and a SCT
	// list extension is inserted in its place. Except for this and the signature
	// the final certificate exactly matches the precertificate.
	//
	// It's critical not to sign two different final certificates for the same
	// precertificate. That's why this code is inline: the only way to reach this
	// point is to already have generated a unique serial and unique precert; if
	// any of the previous steps returned an error, then the whole certificate
	// issuance attempt fails and any subsequent attempt to reach this code will
	// generate a new serial.
	certReq, err := issuance.RequestFromPrecert(precert, scts)
	if err != nil {
		return nil, err
	}

	lintCertDER, issuanceToken, err := issuer.Prepare(profile, certReq)
	if err != nil {
		ca.log.AuditErrf("Preparing cert failed: serial=[%s] err=[%v]", serialHex, err)
		return nil, fmt.Errorf("failed to prepare certificate signing: %w", err)
	}

	ca.log.AuditObject("Signing cert", issuanceEvent{
		Requester:       req.RegistrationID,
		OrderID:         req.OrderID,
		Profile:         req.CertProfileName,
		Issuer:          issuer.Name(),
		IssuanceRequest: certReq,
	})

	certDER, err := issuer.Issue(issuanceToken)
	if err != nil {
		ca.metrics.noteSignError(err)
		ca.log.AuditErrf("Signing cert failed: serial=[%s] err=[%v]", serialHex, err)
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}
	ca.metrics.signatureCount.With(prometheus.Labels{"purpose": string(certType), "issuer": issuer.Name()}).Inc()
	ca.metrics.certificates.With(prometheus.Labels{"profile": req.CertProfileName}).Inc()

	ca.log.AuditObject("Signing cert success", issuanceEvent{
		Requester:       req.RegistrationID,
		OrderID:         req.OrderID,
		Profile:         req.CertProfileName,
		Issuer:          issuer.Name(),
		IssuanceRequest: certReq,
		Result:          issuanceEventResult{Certificate: hex.EncodeToString(certDER)},
	})

	err = tbsCertIsDeterministic(lintCertDER, certDER)
	if err != nil {
		return nil, err
	}

	_, err = ca.sa.AddCertificate(ctx, &sapb.AddCertificateRequest{
		Der:    certDER,
		RegID:  req.RegistrationID,
		Issued: timestamppb.New(ca.clk.Now()),
	})
	if err != nil {
		ca.log.AuditErrf("Failed RPC to store at SA: serial=[%s] err=[%v]", serialHex, err)
		return nil, fmt.Errorf("persisting cert to database: %w", err)
	}

	return &capb.IssueCertificateResponse{DER: certDER}, nil
}

// pickIssuer returns an issuer which is willing to issue certificates for the
// given profile and public key algorithm. If no such issuer exists, it returns
// an error. If multiple such issuers exist, it selects one at random.
func (ca *certificateAuthorityImpl) pickIssuer(profileName string, keyAlg x509.PublicKeyAlgorithm) (*issuance.Issuer, error) {
	var pool []*issuance.Issuer
	for _, issuer := range ca.issuers {
		if !issuer.IsActive() {
			continue
		}
		if issuer.KeyType() != keyAlg {
			continue
		}
		if !slices.Contains(issuer.Profiles(), profileName) {
			continue
		}
		pool = append(pool, issuer)
	}

	if len(pool) == 0 {
		return nil, fmt.Errorf("no issuer found for profile %q and key algorithm %s", profileName, keyAlg)
	}

	return pool[mrand.IntN(len(pool))], nil
}

// generateSerialNumber produces a big.Int which has more than 64 bits of
// entropy and has the CA's configured one-byte prefix.
func (ca *certificateAuthorityImpl) generateSerialNumber() (*big.Int, error) {
	// We want 136 bits of random number, plus an 8-bit instance id prefix.
	const randBits = 136
	serialBytes := make([]byte, randBits/8+1)
	serialBytes[0] = ca.prefix
	_, err := rand.Read(serialBytes[1:])
	if err != nil {
		err = berrors.InternalServerError("failed to generate serial: %s", err)
		ca.log.AuditErrf("Serial randomness failed, err=[%v]", err)
		return nil, err
	}
	serialBigInt := big.NewInt(0)
	serialBigInt = serialBigInt.SetBytes(serialBytes)

	return serialBigInt, nil
}

// generateSKID computes the Subject Key Identifier using one of the methods in
// RFC 7093 Section 2 Additional Methods for Generating Key Identifiers:
// The keyIdentifier [may be] composed of the leftmost 160-bits of the
// SHA-256 hash of the value of the BIT STRING subjectPublicKey
// (excluding the tag, length, and number of unused bits).
func generateSKID(pk crypto.PublicKey) ([]byte, error) {
	pkBytes, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return nil, err
	}

	var pkixPublicKey struct {
		Algo      pkix.AlgorithmIdentifier
		BitString asn1.BitString
	}
	if _, err := asn1.Unmarshal(pkBytes, &pkixPublicKey); err != nil {
		return nil, err
	}

	skid := sha256.Sum256(pkixPublicKey.BitString.Bytes)
	return skid[0:20:20], nil
}

// verifyTBSCertIsDeterministic verifies that x509.CreateCertificate signing
// operation is deterministic and produced identical DER bytes between the given
// lint certificate and leaf certificate. If the DER byte equality check fails
// it's mississuance, but it's better to know about the problem sooner than
// later. The caller is responsible for passing the appropriate valid
// certificate bytes in the correct position.
func tbsCertIsDeterministic(lintCertBytes []byte, leafCertBytes []byte) error {
	if core.IsAnyNilOrZero(lintCertBytes, leafCertBytes) {
		return fmt.Errorf("lintCertBytes of leafCertBytes were nil")
	}

	// extractTBSCertBytes is a partial copy of //crypto/x509/parser.go to
	// extract the RawTBSCertificate field from given DER bytes. It the
	// RawTBSCertificate field bytes or an error if the given bytes cannot be
	// parsed. This is far more performant than parsing the entire *Certificate
	// structure with x509.ParseCertificate().
	//
	// RFC 5280, Section 4.1
	//    Certificate  ::=  SEQUENCE  {
	//      tbsCertificate       TBSCertificate,
	//      signatureAlgorithm   AlgorithmIdentifier,
	//      signatureValue       BIT STRING  }
	//
	//    TBSCertificate  ::=  SEQUENCE  {
	//      ..
	extractTBSCertBytes := func(inputDERBytes *[]byte) ([]byte, error) {
		input := cryptobyte.String(*inputDERBytes)

		// Extract the Certificate bytes
		if !input.ReadASN1(&input, cryptobyte_asn1.SEQUENCE) {
			return nil, errors.New("malformed certificate")
		}

		var tbs cryptobyte.String
		// Extract the TBSCertificate bytes from the Certificate bytes
		if !input.ReadASN1(&tbs, cryptobyte_asn1.SEQUENCE) {
			return nil, errors.New("malformed tbs certificate")
		}

		if tbs.Empty() {
			return nil, errors.New("parsed RawTBSCertificate field was empty")
		}

		return tbs, nil
	}

	lintRawTBSCert, err := extractTBSCertBytes(&lintCertBytes)
	if err != nil {
		return fmt.Errorf("while extracting lint TBS cert: %w", err)
	}

	leafRawTBSCert, err := extractTBSCertBytes(&leafCertBytes)
	if err != nil {
		return fmt.Errorf("while extracting leaf TBS cert: %w", err)
	}

	if !bytes.Equal(lintRawTBSCert, leafRawTBSCert) {
		return fmt.Errorf("mismatch between lintCert and leafCert RawTBSCertificate DER bytes: \"%x\" != \"%x\"", lintRawTBSCert, leafRawTBSCert)
	}

	return nil
}
