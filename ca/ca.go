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
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	mrand "math/rand/v2"
	"time"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	"github.com/jmhodges/clock"
	"github.com/miekg/pkcs11"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/ocsp"
	"google.golang.org/protobuf/types/known/timestamppb"

	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	csrlib "github.com/letsencrypt/boulder/csr"
	berrors "github.com/letsencrypt/boulder/errors"
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

// issuanceEvent is logged before and after issuance of precertificates and certificates.
// The `omitempty` fields are not always present.
// CSR, Precertificate, and Certificate are hex-encoded DER bytes to make it easier to
// ad-hoc search for sequences or OIDs in logs. Other data, like public key within CSR,
// is logged as base64 because it doesn't have interesting DER structure.
type issuanceEvent struct {
	CSR             string `json:",omitempty"`
	IssuanceRequest *issuance.IssuanceRequest
	Issuer          string
	OrderID         int64
	Profile         string
	ProfileHash     string
	Requester       int64
	Result          struct {
		Precertificate string `json:",omitempty"`
		Certificate    string `json:",omitempty"`
	}
}

// Two maps of keys to Issuers. Lookup by PublicKeyAlgorithm is useful for
// determining the set of issuers which can sign a given (pre)cert, based on its
// PublicKeyAlgorithm. Lookup by NameID is useful for looking up a specific
// issuer based on the issuer of a given (pre)certificate.
type issuerMaps struct {
	byAlg    map[x509.PublicKeyAlgorithm][]*issuance.Issuer
	byNameID map[issuance.NameID]*issuance.Issuer
}

type certProfileWithID struct {
	// name is a human readable name used to refer to the certificate profile.
	name string
	// hash is SHA256 sum over every exported field of an issuance.ProfileConfig
	// used to generate the embedded *issuance.Profile.
	hash    [32]byte
	profile *issuance.Profile
}

// certProfilesMaps allows looking up the human-readable name of a certificate
// profile to retrieve the actual profile. The default profile to be used is
// stored alongside the maps.
type certProfilesMaps struct {
	// The name of the profile that will be selected if no explicit profile name
	// is provided via gRPC.
	defaultName string

	profileByHash map[[32]byte]*certProfileWithID
	profileByName map[string]*certProfileWithID
}

// caMetrics holds various metrics which are shared between caImpl, ocspImpl,
// and crlImpl.
type caMetrics struct {
	signatureCount *prometheus.CounterVec
	signErrorCount *prometheus.CounterVec
	lintErrorCount prometheus.Counter
}

func NewCAMetrics(stats prometheus.Registerer) *caMetrics {
	signatureCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "signatures",
			Help: "Number of signatures",
		},
		[]string{"purpose", "issuer"})
	stats.MustRegister(signatureCount)

	signErrorCount := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "signature_errors",
		Help: "A counter of signature errors labelled by error type",
	}, []string{"type"})
	stats.MustRegister(signErrorCount)

	lintErrorCount := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "lint_errors",
			Help: "Number of issuances that were halted by linting errors",
		})
	stats.MustRegister(lintErrorCount)

	return &caMetrics{signatureCount, signErrorCount, lintErrorCount}
}

func (m *caMetrics) noteSignError(err error) {
	var pkcs11Error pkcs11.Error
	if errors.As(err, &pkcs11Error) {
		m.signErrorCount.WithLabelValues("HSM").Inc()
	}
}

// certificateAuthorityImpl represents a CA that signs certificates.
// It can sign OCSP responses as well, but only via delegation to an ocspImpl.
type certificateAuthorityImpl struct {
	capb.UnsafeCertificateAuthorityServer
	sa           sapb.StorageAuthorityCertificateClient
	pa           core.PolicyAuthority
	issuers      issuerMaps
	certProfiles certProfilesMaps

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

// makeIssuerMaps processes a list of issuers into a set of maps for easy
// lookup either by key algorithm (useful for picking an issuer for a precert)
// or by unique ID (useful for final certs, OCSP, and CRLs). If two issuers with
// the same unique ID are encountered, an error is returned.
func makeIssuerMaps(issuers []*issuance.Issuer) (issuerMaps, error) {
	issuersByAlg := make(map[x509.PublicKeyAlgorithm][]*issuance.Issuer, 2)
	issuersByNameID := make(map[issuance.NameID]*issuance.Issuer, len(issuers))
	for _, issuer := range issuers {
		if _, found := issuersByNameID[issuer.NameID()]; found {
			return issuerMaps{}, fmt.Errorf("two issuers with same NameID %d (%s) configured", issuer.NameID(), issuer.Name())
		}
		issuersByNameID[issuer.NameID()] = issuer
		if issuer.IsActive() {
			issuersByAlg[issuer.KeyType()] = append(issuersByAlg[issuer.KeyType()], issuer)
		}
	}
	if i, ok := issuersByAlg[x509.ECDSA]; !ok || len(i) == 0 {
		return issuerMaps{}, errors.New("no ECDSA issuers configured")
	}
	if i, ok := issuersByAlg[x509.RSA]; !ok || len(i) == 0 {
		return issuerMaps{}, errors.New("no RSA issuers configured")
	}
	return issuerMaps{issuersByAlg, issuersByNameID}, nil
}

// makeCertificateProfilesMap processes a set of named certificate issuance
// profile configs into a two pre-computed maps: 1) a human-readable name to the
// profile and 2) a unique hash over contents of the profile to the profile
// itself. It returns the maps or an error if a duplicate name or hash is found.
//
// The unique hash is used in the case of
//   - RA instructs CA1 to issue a precertificate
//   - CA1 returns the precertificate DER bytes and profile hash to the RA
//   - RA instructs CA2 to issue a final certificate, but CA2 does not contain a
//     profile corresponding to that hash and an issuance is prevented.
func makeCertificateProfilesMap(defaultName string, profiles map[string]*issuance.ProfileConfig) (certProfilesMaps, error) {
	if len(profiles) <= 0 {
		return certProfilesMaps{}, fmt.Errorf("must pass at least one certificate profile")
	}

	// Check that a profile exists with the configured default profile name.
	_, ok := profiles[defaultName]
	if !ok {
		return certProfilesMaps{}, fmt.Errorf("defaultCertificateProfileName:\"%s\" was configured, but a profile object was not found for that name", defaultName)
	}

	profilesByName := make(map[string]*certProfileWithID, len(profiles))
	profilesByHash := make(map[[32]byte]*certProfileWithID, len(profiles))

	for name, profileConfig := range profiles {
		profile, err := issuance.NewProfile(profileConfig)
		if err != nil {
			return certProfilesMaps{}, err
		}

		// gob can only encode exported fields, of which an issuance.Profile has
		// none. However, since we're already in a loop iteration having access
		// to the issuance.ProfileConfig used to generate the issuance.Profile,
		// we'll generate the hash from that.
		var encodedProfile bytes.Buffer
		enc := gob.NewEncoder(&encodedProfile)
		err = enc.Encode(profileConfig)
		if err != nil {
			return certProfilesMaps{}, err
		}
		if len(encodedProfile.Bytes()) <= 0 {
			return certProfilesMaps{}, fmt.Errorf("certificate profile encoding returned 0 bytes")
		}
		hash := sha256.Sum256(encodedProfile.Bytes())

		withID := certProfileWithID{
			name:    name,
			hash:    hash,
			profile: profile,
		}

		profilesByName[name] = &withID

		_, found := profilesByHash[hash]
		if found {
			return certProfilesMaps{}, fmt.Errorf("duplicate certificate profile hash %d", hash)
		}
		profilesByHash[hash] = &withID
	}

	return certProfilesMaps{defaultName, profilesByHash, profilesByName}, nil
}

// NewCertificateAuthorityImpl creates a CA instance that can sign certificates
// from any number of issuance.Issuers according to their profiles, and can sign
// OCSP (via delegation to an ocspImpl and its issuers).
func NewCertificateAuthorityImpl(
	sa sapb.StorageAuthorityCertificateClient,
	pa core.PolicyAuthority,
	boulderIssuers []*issuance.Issuer,
	defaultCertProfileName string,
	certificateProfiles map[string]*issuance.ProfileConfig,
	serialPrefix byte,
	maxNames int,
	keyPolicy goodkey.KeyPolicy,
	logger blog.Logger,
	metrics *caMetrics,
	clk clock.Clock,
) (*certificateAuthorityImpl, error) {
	var ca *certificateAuthorityImpl
	var err error

	if serialPrefix < 0x01 || serialPrefix > 0x7f {
		err = errors.New("serial prefix must be between 0x01 (1) and 0x7f (127)")
		return nil, err
	}

	if len(boulderIssuers) == 0 {
		return nil, errors.New("must have at least one issuer")
	}

	certProfiles, err := makeCertificateProfilesMap(defaultCertProfileName, certificateProfiles)
	if err != nil {
		return nil, err
	}

	issuers, err := makeIssuerMaps(boulderIssuers)
	if err != nil {
		return nil, err
	}

	ca = &certificateAuthorityImpl{
		sa:           sa,
		pa:           pa,
		issuers:      issuers,
		certProfiles: certProfiles,
		prefix:       serialPrefix,
		maxNames:     maxNames,
		keyPolicy:    keyPolicy,
		log:          logger,
		metrics:      metrics,
		tracer:       otel.GetTracerProvider().Tracer("github.com/letsencrypt/boulder/ca"),
		clk:          clk,
	}

	return ca, nil
}

var ocspStatusToCode = map[string]int{
	"good":    ocsp.Good,
	"revoked": ocsp.Revoked,
	"unknown": ocsp.Unknown,
}

// IssuePrecertificate is the first step in the [issuance cycle]. It allocates and stores a serial number,
// selects a certificate profile, generates and stores a linting certificate, sets the serial's status to
// "wait", signs and stores a precertificate, updates the serial's status to "good", then returns the
// precertificate.
//
// Subsequent final issuance based on this precertificate must happen at most once, and must use the same
// certificate profile. The certificate profile is identified by a hash to ensure an exact match even if
// the configuration for a specific profile _name_ changes.
//
// [issuance cycle]: https://github.com/letsencrypt/boulder/blob/main/docs/ISSUANCE-CYCLE.md
func (ca *certificateAuthorityImpl) IssuePrecertificate(ctx context.Context, issueReq *capb.IssueCertificateRequest) (*capb.IssuePrecertificateResponse, error) {
	// issueReq.orderID may be zero, for ACMEv1 requests.
	if core.IsAnyNilOrZero(issueReq, issueReq.Csr, issueReq.RegistrationID) {
		return nil, berrors.InternalServerError("Incomplete issue certificate request")
	}

	// The CA must check if it is capable of issuing for the given certificate
	// profile name. The name is checked here instead of the hash because the RA
	// is unaware of what certificate profiles exist. Pre-existing orders stored
	// in the database may not have an associated certificate profile name and
	// will take the default name stored alongside the map.
	if issueReq.CertProfileName == "" {
		issueReq.CertProfileName = ca.certProfiles.defaultName
	}
	certProfile, ok := ca.certProfiles.profileByName[issueReq.CertProfileName]
	if !ok {
		return nil, fmt.Errorf("the CA is incapable of using a profile named %s", issueReq.CertProfileName)
	}

	serialBigInt, err := ca.generateSerialNumber()
	if err != nil {
		return nil, err
	}

	notBefore, notAfter := certProfile.profile.GenerateValidity(ca.clk.Now())

	serialHex := core.SerialToString(serialBigInt)
	regID := issueReq.RegistrationID
	_, err = ca.sa.AddSerial(ctx, &sapb.AddSerialRequest{
		Serial:  serialHex,
		RegID:   regID,
		Created: timestamppb.New(ca.clk.Now()),
		Expires: timestamppb.New(notAfter),
	})
	if err != nil {
		return nil, err
	}

	precertDER, cpwid, err := ca.issuePrecertificateInner(ctx, issueReq, certProfile, serialBigInt, notBefore, notAfter)
	if err != nil {
		return nil, err
	}

	_, err = ca.sa.SetCertificateStatusReady(ctx, &sapb.Serial{Serial: serialHex})
	if err != nil {
		return nil, err
	}

	return &capb.IssuePrecertificateResponse{
		DER:             precertDER,
		CertProfileName: cpwid.name,
		CertProfileHash: cpwid.hash[:],
	}, nil
}

// IssueCertificateForPrecertificate final step in the [issuance cycle].
//
// Given a precertificate and a set of SCTs for that precertificate, it generates
// a linting final certificate, then signs a final certificate using a real issuer.
// The poison extension is removed from the precertificate and a
// SCT list extension is inserted in its place. Except for this and the
// signature the final certificate exactly matches the precertificate.
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
//
// [issuance cycle]: https://github.com/letsencrypt/boulder/blob/main/docs/ISSUANCE-CYCLE.md
func (ca *certificateAuthorityImpl) IssueCertificateForPrecertificate(ctx context.Context, req *capb.IssueCertificateForPrecertificateRequest) (*corepb.Certificate, error) {
	// issueReq.orderID may be zero, for ACMEv1 requests.
	if core.IsAnyNilOrZero(req, req.DER, req.SCTs, req.RegistrationID, req.CertProfileHash) {
		return nil, berrors.InternalServerError("Incomplete cert for precertificate request")
	}

	// The certificate profile hash is checked here instead of the name because
	// the hash is over the entire contents of a *ProfileConfig giving assurance
	// that the certificate profile has remained unchanged during the roundtrip
	// from a CA, to the RA, then back to a (potentially different) CA node.
	certProfile, ok := ca.certProfiles.profileByHash[[32]byte(req.CertProfileHash)]
	if !ok {
		return nil, fmt.Errorf("the CA is incapable of using a profile with hash %d", req.CertProfileHash)
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

	issuer, ok := ca.issuers.byNameID[issuance.IssuerNameID(precert)]
	if !ok {
		return nil, berrors.InternalServerError("no issuer found for Issuer Name %s", precert.Issuer)
	}

	issuanceReq, err := issuance.RequestFromPrecert(precert, scts)
	if err != nil {
		return nil, err
	}

	lintCertBytes, issuanceToken, err := issuer.Prepare(certProfile.profile, issuanceReq)
	if err != nil {
		ca.log.AuditErrf("Preparing cert failed: serial=[%s] err=[%v]", serialHex, err)
		return nil, berrors.InternalServerError("failed to prepare certificate signing: %s", err)
	}

	logEvent := issuanceEvent{
		IssuanceRequest: issuanceReq,
		Issuer:          issuer.Name(),
		OrderID:         req.OrderID,
		Profile:         certProfile.name,
		ProfileHash:     hex.EncodeToString(certProfile.hash[:]),
		Requester:       req.RegistrationID,
	}
	ca.log.AuditObject("Signing cert", logEvent)

	_, span := ca.tracer.Start(ctx, "signing cert", trace.WithAttributes(
		attribute.String("serial", serialHex),
		attribute.String("issuer", issuer.Name()),
		attribute.String("certProfileName", certProfile.name),
		attribute.StringSlice("names", issuanceReq.DNSNames),
	))
	certDER, err := issuer.Issue(issuanceToken)
	if err != nil {
		ca.metrics.noteSignError(err)
		ca.log.AuditErrf("Signing cert failed: serial=[%s] err=[%v]", serialHex, err)
		span.SetStatus(codes.Error, err.Error())
		span.End()
		return nil, berrors.InternalServerError("failed to sign certificate: %s", err)
	}
	span.End()

	err = tbsCertIsDeterministic(lintCertBytes, certDER)
	if err != nil {
		return nil, err
	}

	ca.metrics.signatureCount.With(prometheus.Labels{"purpose": string(certType), "issuer": issuer.Name()}).Inc()
	logEvent.Result.Certificate = hex.EncodeToString(certDER)
	ca.log.AuditObject("Signing cert success", logEvent)

	_, err = ca.sa.AddCertificate(ctx, &sapb.AddCertificateRequest{
		Der:    certDER,
		RegID:  req.RegistrationID,
		Issued: timestamppb.New(ca.clk.Now()),
	})
	if err != nil {
		ca.log.AuditErrf("Failed RPC to store at SA: serial=[%s] err=[%v]", serialHex, hex.EncodeToString(certDER))
		return nil, err
	}

	return &corepb.Certificate{
		RegistrationID: req.RegistrationID,
		Serial:         core.SerialToString(precert.SerialNumber),
		Der:            certDER,
		Digest:         core.Fingerprint256(certDER),
		Issued:         timestamppb.New(precert.NotBefore),
		Expires:        timestamppb.New(precert.NotAfter),
	}, nil
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

func (ca *certificateAuthorityImpl) issuePrecertificateInner(ctx context.Context, issueReq *capb.IssueCertificateRequest, certProfile *certProfileWithID, serialBigInt *big.Int, notBefore time.Time, notAfter time.Time) ([]byte, *certProfileWithID, error) {
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

	// Select which pool of issuers to use, based on the to-be-issued cert's key
	// type.
	alg := csr.PublicKeyAlgorithm

	// Select a random issuer from among the active issuers of this key type.
	issuerPool, ok := ca.issuers.byAlg[alg]
	if !ok || len(issuerPool) == 0 {
		return nil, nil, berrors.InternalServerError("no issuers found for public key algorithm %s", csr.PublicKeyAlgorithm)
	}
	issuer := issuerPool[mrand.IntN(len(issuerPool))]

	if issuer.Cert.NotAfter.Before(notAfter) {
		err = berrors.InternalServerError("cannot issue a certificate that expires after the issuer certificate")
		ca.log.AuditErr(err.Error())
		return nil, nil, err
	}

	subjectKeyId, err := generateSKID(csr.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("computing subject key ID: %w", err)
	}

	serialHex := core.SerialToString(serialBigInt)

	names := csrlib.NamesFromCSR(csr)
	req := &issuance.IssuanceRequest{
		PublicKey:         issuance.MarshalablePublicKey{PublicKey: csr.PublicKey},
		SubjectKeyId:      subjectKeyId,
		Serial:            serialBigInt.Bytes(),
		DNSNames:          names.SANs,
		CommonName:        names.CN,
		IncludeCTPoison:   true,
		IncludeMustStaple: issuance.ContainsMustStaple(csr.Extensions),
		NotBefore:         notBefore,
		NotAfter:          notAfter,
	}

	lintCertBytes, issuanceToken, err := issuer.Prepare(certProfile.profile, req)
	if err != nil {
		ca.log.AuditErrf("Preparing precert failed: serial=[%s] err=[%v]", serialHex, err)
		if errors.Is(err, linter.ErrLinting) {
			ca.metrics.lintErrorCount.Inc()
		}
		return nil, nil, berrors.InternalServerError("failed to prepare precertificate signing: %s", err)
	}

	// Note: we write the linting certificate bytes to this table, rather than the precertificate
	// (which we audit log but do not put in the database). This is to ensure that even if there is
	// an error immediately after signing the precertificate, we have a record in the DB of what we
	// intended to sign, and can do revocations based on that. See #6807.
	// The name of the SA method ("AddPrecertificate") is a historical artifact.
	_, err = ca.sa.AddPrecertificate(context.Background(), &sapb.AddCertificateRequest{
		Der:          lintCertBytes,
		RegID:        issueReq.RegistrationID,
		Issued:       timestamppb.New(ca.clk.Now()),
		IssuerNameID: int64(issuer.NameID()),
		OcspNotReady: true,
	})
	if err != nil {
		return nil, nil, err
	}

	logEvent := issuanceEvent{
		CSR:             hex.EncodeToString(csr.Raw),
		IssuanceRequest: req,
		Issuer:          issuer.Name(),
		Profile:         certProfile.name,
		ProfileHash:     hex.EncodeToString(certProfile.hash[:]),
		Requester:       issueReq.RegistrationID,
		OrderID:         issueReq.OrderID,
	}
	ca.log.AuditObject("Signing precert", logEvent)

	_, span := ca.tracer.Start(ctx, "signing precert", trace.WithAttributes(
		attribute.String("serial", serialHex),
		attribute.String("issuer", issuer.Name()),
		attribute.String("certProfileName", certProfile.name),
		attribute.StringSlice("names", csr.DNSNames),
	))
	certDER, err := issuer.Issue(issuanceToken)
	if err != nil {
		ca.metrics.noteSignError(err)
		ca.log.AuditErrf("Signing precert failed: serial=[%s] err=[%v]", serialHex, err)
		span.SetStatus(codes.Error, err.Error())
		span.End()
		return nil, nil, berrors.InternalServerError("failed to sign precertificate: %s", err)
	}
	span.End()

	err = tbsCertIsDeterministic(lintCertBytes, certDER)
	if err != nil {
		return nil, nil, err
	}

	ca.metrics.signatureCount.With(prometheus.Labels{"purpose": string(precertType), "issuer": issuer.Name()}).Inc()

	logEvent.Result.Precertificate = hex.EncodeToString(certDER)
	// The CSR is big and not that informative, so don't log it a second time.
	logEvent.CSR = ""
	ca.log.AuditObject("Signing precert success", logEvent)

	return certDER, &certProfileWithID{certProfile.name, certProfile.hash, nil}, nil
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
