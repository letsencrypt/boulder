// Package local implements certificate signature functionality for CFSSL.
package local

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/mail"
	"os"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/config"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/info"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"golang.org/x/net/context"
	"time"
)

// Signer contains a signer that uses the standard library to
// support both ECDSA and RSA CA keys.
type Signer struct {
	ca         *x509.Certificate
	priv       crypto.Signer
	policy     *config.Signing
	sigAlgo    x509.SignatureAlgorithm
	dbAccessor certdb.Accessor
}

// NewSigner creates a new Signer directly from a
// private key and certificate, with optional policy.
func NewSigner(priv crypto.Signer, cert *x509.Certificate, sigAlgo x509.SignatureAlgorithm, policy *config.Signing) (*Signer, error) {
	if policy == nil {
		policy = &config.Signing{
			Profiles: map[string]*config.SigningProfile{},
			Default:  config.DefaultConfig()}
	}

	if !policy.Valid() {
		return nil, cferr.New(cferr.PolicyError, cferr.InvalidPolicy)
	}

	return &Signer{
		ca:      cert,
		priv:    priv,
		sigAlgo: sigAlgo,
		policy:  policy,
	}, nil
}

// NewSignerFromFile generates a new local signer from a caFile
// and a caKey file, both PEM encoded.
func NewSignerFromFile(caFile, caKeyFile string, policy *config.Signing) (*Signer, error) {
	log.Debug("Loading CA: ", caFile)
	ca, err := helpers.ReadBytes(caFile)
	if err != nil {
		return nil, err
	}
	log.Debug("Loading CA key: ", caKeyFile)
	cakey, err := helpers.ReadBytes(caKeyFile)
	if err != nil {
		return nil, cferr.Wrap(cferr.CertificateError, cferr.ReadFailed, err)
	}

	parsedCa, err := helpers.ParseCertificatePEM(ca)
	if err != nil {
		return nil, err
	}

	strPassword := os.Getenv("CFSSL_CA_PK_PASSWORD")
	password := []byte(strPassword)
	if strPassword == "" {
		password = nil
	}

	priv, err := helpers.ParsePrivateKeyPEMWithPassword(cakey, password)
	if err != nil {
		log.Debug("Malformed private key %v", err)
		return nil, err
	}

	return NewSigner(priv, parsedCa, signer.DefaultSigAlgo(priv), policy)
}

func (s *Signer) sign(template *x509.Certificate, profile *config.SigningProfile, notBefore time.Time, notAfter time.Time) ([]byte, error) {
	var distPoints= template.CRLDistributionPoints
	if distPoints != nil && len(distPoints) > 0 {
		template.CRLDistributionPoints = distPoints
	}
	err := signer.FillTemplate(template, s.policy.Default, profile, notBefore, notAfter)
	if err != nil {
		return nil, err
	}

	var initRoot bool
	if s.ca == nil {
		if !template.IsCA {
			return nil, cferr.New(cferr.PolicyError, cferr.InvalidRequest)
		}
		template.DNSNames = nil
		template.EmailAddresses = nil
		s.ca = template
		initRoot = true
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, s.ca, template.PublicKey, s.priv)
	if err != nil {
		return nil, cferr.Wrap(cferr.CertificateError, cferr.Unknown, err)
	}
	if initRoot {
		s.ca, err = x509.ParseCertificate(derBytes)
		if err != nil {
			return nil, cferr.Wrap(cferr.CertificateError, cferr.ParseFailed, err)
		}
	}

	log.Infof("signed certificate with serial number %d", template.SerialNumber)
	return derBytes, nil
}

// replaceSliceIfEmpty replaces the contents of replaced with newContents if
// the slice referenced by replaced is empty
func replaceSliceIfEmpty(replaced, newContents *[]string) {
	if len(*replaced) == 0 {
		*replaced = *newContents
	}
}

// PopulateSubjectFromCSR has functionality similar to Name, except
// it fills the fields of the resulting pkix.Name with req's if the
// subject's corresponding fields are empty
func PopulateSubjectFromCSR(s *signer.Subject, req pkix.Name) pkix.Name {
	// if no subject, use req
	if s == nil {
		return req
	}

	name := s.Name()

	if name.CommonName == "" {
		name.CommonName = req.CommonName
	}

	replaceSliceIfEmpty(&name.Country, &req.Country)
	replaceSliceIfEmpty(&name.Province, &req.Province)
	replaceSliceIfEmpty(&name.Locality, &req.Locality)
	replaceSliceIfEmpty(&name.Organization, &req.Organization)
	replaceSliceIfEmpty(&name.OrganizationalUnit, &req.OrganizationalUnit)
	if name.SerialNumber == "" {
		name.SerialNumber = req.SerialNumber
	}
	return name
}

// OverrideHosts fills template's IPAddresses, EmailAddresses, and DNSNames with the
// content of hosts, if it is not nil.
func OverrideHosts(template *x509.Certificate, hosts []string) {
	if hosts != nil {
		template.IPAddresses = []net.IP{}
		template.EmailAddresses = []string{}
		template.DNSNames = []string{}
	}

	for i := range hosts {
		if ip := net.ParseIP(hosts[i]); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(hosts[i]); err == nil && email != nil {
			template.EmailAddresses = append(template.EmailAddresses, email.Address)
		} else {
			template.DNSNames = append(template.DNSNames, hosts[i])
		}
	}

}

// Sign signs a new certificate based on the PEM-encoded client
// certificate or certificate request with the signing profile,
// specified by profileName.
func (s *Signer) Sign(req signer.SignRequest) ([]byte, error) {
	profile, err := signer.Profile(s, req.Profile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(req.Request))
	if block == nil {
		return nil, cferr.New(cferr.CSRError, cferr.DecodeFailed)
	}

	if block.Type != "NEW CERTIFICATE REQUEST" && block.Type != "CERTIFICATE REQUEST" {
		return nil, cferr.Wrap(cferr.CSRError,
			cferr.BadRequest, errors.New("not a csr"))
	}

	csrTemplate, err := signer.ParseCertificateRequest(s, block.Bytes)
	if err != nil {
		return nil, err
	}

	// Copy out only the fields from the CSR authorized by policy.
	safeTemplate := x509.Certificate{}
	// If the profile contains no explicit whitelist, assume that all fields
	// should be copied from the CSR.
	if profile.CSRWhitelist == nil {
		safeTemplate = *csrTemplate
	} else {
		if profile.CSRWhitelist.Subject {
			safeTemplate.Subject = csrTemplate.Subject
		}
		if profile.CSRWhitelist.PublicKeyAlgorithm {
			safeTemplate.PublicKeyAlgorithm = csrTemplate.PublicKeyAlgorithm
		}
		if profile.CSRWhitelist.PublicKey {
			safeTemplate.PublicKey = csrTemplate.PublicKey
		}
		if profile.CSRWhitelist.SignatureAlgorithm {
			safeTemplate.SignatureAlgorithm = csrTemplate.SignatureAlgorithm
		}
		if profile.CSRWhitelist.DNSNames {
			safeTemplate.DNSNames = csrTemplate.DNSNames
		}
		if profile.CSRWhitelist.IPAddresses {
			safeTemplate.IPAddresses = csrTemplate.IPAddresses
		}
		if profile.CSRWhitelist.EmailAddresses {
			safeTemplate.EmailAddresses = csrTemplate.EmailAddresses
		}
	}

	if req.CRLOverride != "" {
		safeTemplate.CRLDistributionPoints = []string{req.CRLOverride}
	}

	if safeTemplate.IsCA {
		if !profile.CAConstraint.IsCA {
			log.Error("local signer policy disallows issuing CA certificate")
			return nil, cferr.New(cferr.PolicyError, cferr.InvalidRequest)
		}

		if s.ca != nil && s.ca.MaxPathLen > 0 {
			if safeTemplate.MaxPathLen >= s.ca.MaxPathLen {
				log.Error("local signer certificate disallows CA MaxPathLen extending")
				// do not sign a cert with pathlen > current
				return nil, cferr.New(cferr.PolicyError, cferr.InvalidRequest)
			}
		} else if s.ca != nil && s.ca.MaxPathLen == 0 && s.ca.MaxPathLenZero {
			log.Error("local signer certificate disallows issuing CA certificate")
			// signer has pathlen of 0, do not sign more intermediate CAs
			return nil, cferr.New(cferr.PolicyError, cferr.InvalidRequest)
		}
	}

	OverrideHosts(&safeTemplate, req.Hosts)
	safeTemplate.Subject = PopulateSubjectFromCSR(req.Subject, safeTemplate.Subject)

	// If there is a whitelist, ensure that both the Common Name and SAN DNSNames match
	if profile.NameWhitelist != nil {
		if safeTemplate.Subject.CommonName != "" {
			if profile.NameWhitelist.Find([]byte(safeTemplate.Subject.CommonName)) == nil {
				return nil, cferr.New(cferr.PolicyError, cferr.UnmatchedWhitelist)
			}
		}
		for _, name := range safeTemplate.DNSNames {
			if profile.NameWhitelist.Find([]byte(name)) == nil {
				return nil, cferr.New(cferr.PolicyError, cferr.UnmatchedWhitelist)
			}
		}
		for _, name := range safeTemplate.EmailAddresses {
			if profile.NameWhitelist.Find([]byte(name)) == nil {
				return nil, cferr.New(cferr.PolicyError, cferr.UnmatchedWhitelist)
			}
		}
	}

	if profile.ClientProvidesSerialNumbers {
		if req.Serial == nil {
			return nil, cferr.New(cferr.CertificateError, cferr.MissingSerial)
		}
		safeTemplate.SerialNumber = req.Serial
	} else {
		// RFC 5280 4.1.2.2:
		// Certificate users MUST be able to handle serialNumber
		// values up to 20 octets.  Conforming CAs MUST NOT use
		// serialNumber values longer than 20 octets.
		//
		// If CFSSL is providing the serial numbers, it makes
		// sense to use the max supported size.
		serialNumber := make([]byte, 20)
		_, err = io.ReadFull(rand.Reader, serialNumber)
		if err != nil {
			return nil, cferr.Wrap(cferr.CertificateError, cferr.Unknown, err)
		}

		// SetBytes interprets buf as the bytes of a big-endian
		// unsigned integer. The leading byte should be masked
		// off to ensure it isn't negative.
		serialNumber[0] &= 0x7F

		safeTemplate.SerialNumber = new(big.Int).SetBytes(serialNumber)
	}

	if len(req.Extensions) > 0 {
		for _, ext := range req.Extensions {
			oid := asn1.ObjectIdentifier(ext.ID)
			if !profile.ExtensionWhitelist[oid.String()] {
				return nil, cferr.New(cferr.CertificateError, cferr.InvalidRequest)
			}

			rawValue, err := hex.DecodeString(ext.Value)
			if err != nil {
				return nil, cferr.Wrap(cferr.CertificateError, cferr.InvalidRequest, err)
			}

			safeTemplate.ExtraExtensions = append(safeTemplate.ExtraExtensions, pkix.Extension{
				Id:       oid,
				Critical: ext.Critical,
				Value:    rawValue,
			})
		}
	}

	var certTBS = safeTemplate

	var precertToMatch *x509.Certificate = nil
	if len(req.PrecertToMatch) > 0 {
		// Serial, NotBefore, and NotAfter must be provided in order for there
		// be any hope for the certificate to match the precertificate. This
		// doesn't need to be explicitly checked since the matching will fail
		// if they aren't provided.

		block, _ := pem.Decode([]byte(req.PrecertToMatch))
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, cferr.New(cferr.CTError, cferr.PrecertParsingFailed)
		}
		precertToMatch, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, cferr.Wrap(cferr.CTError, cferr.PrecertParsingFailed, err)
		}

		if findCTPoisonExtension(precertToMatch) == nil {
			return nil, cferr.New(cferr.CTError, cferr.PrecertNotAPrecert)
		}
	}

	if precertToMatch == nil && len(profile.CTLogServers) > 0 {
		// Add a poison extension which prevents validation
		var poisonExtension = pkix.Extension{Id: signer.CTPoisonOID, Critical: true, Value: []byte{0x05, 0x00}}
		var poisonedPreCert = certTBS
		poisonedPreCert.ExtraExtensions = append(safeTemplate.ExtraExtensions, poisonExtension)
		derCert, err := s.sign(&poisonedPreCert, profile, req.NotBefore, req.NotAfter)
		if err != nil {
			return nil, err
		}

		prechain := []ct.ASN1Cert{{Data: derCert}, {Data: s.ca.Raw}}
		var sctList []ct.SignedCertificateTimestamp

		for _, server := range profile.CTLogServers {
			log.Infof("submitting poisoned precertificate to %s", server)
			ctclient, err := client.New(server, nil, jsonclient.Options{})
			if err != nil {
				return nil, cferr.Wrap(cferr.CTError, cferr.PrecertSubmissionFailed, err)
			}
			var resp *ct.SignedCertificateTimestamp
			ctx := context.Background()
			resp, err = ctclient.AddPreChain(ctx, prechain)
			if err != nil {
				return nil, cferr.Wrap(cferr.CTError, cferr.PrecertSubmissionFailed, err)
			}
			sctList = append(sctList, *resp)
		}

		var serializedSCTList []byte
		serializedSCTList, err = helpers.SerializeSCTList(sctList)
		if err != nil {
			return nil, cferr.Wrap(cferr.CTError, cferr.Unknown, err)
		}

		// Serialize again as an octet string before embedding
		serializedSCTList, err = asn1.Marshal(serializedSCTList)
		if err != nil {
			return nil, cferr.Wrap(cferr.CTError, cferr.Unknown, err)
		}

		var SCTListExtension = pkix.Extension{Id: signer.SCTListOID, Critical: false, Value: serializedSCTList}
		certTBS.ExtraExtensions = append(certTBS.ExtraExtensions, SCTListExtension)
	}
	signedDER, err := s.sign(&certTBS, profile, req.NotBefore, req.NotAfter)
	if err != nil {
		return nil, err
	}

	if precertToMatch != nil {
		// TODO: Check that the certificate and precertificate match *before*
		// signing the certificate.
		err = matchCertWithPrecert(signedDER, precertToMatch)
		if err != nil {
			// Destroy the mismatching certificate to the best of our ability by
			// overwriting it with garbage. We hope rand.Read() isn't optimized
			// away and we intentionally ignore its return value.
			_, _ = rand.Read(signedDER)
			signedDER = []byte{}
			return nil, err
		}
	}

	// Get the AKI from signedCert.  This is required to support Go 1.9+.
	// In prior versions of Go, x509.CreateCertificate updated the
	// AuthorityKeyId of certTBS.
	parsedCert, _ := x509.ParseCertificate(signedDER)

	signedCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signedDER})

	if s.dbAccessor != nil {
		var certRecord = certdb.CertificateRecord{
			Serial: certTBS.SerialNumber.String(),
			// this relies on the specific behavior of x509.CreateCertificate
			// which sets the AuthorityKeyId from the signer's SubjectKeyId
			AKI:     hex.EncodeToString(parsedCert.AuthorityKeyId),
			CALabel: req.Label,
			Status:  "good",
			Expiry:  certTBS.NotAfter,
			PEM:     string(signedCert),
		}

		err = s.dbAccessor.InsertCertificate(certRecord)
		if err != nil {
			return nil, err
		}
		log.Debug("saved certificate with serial number ", certTBS.SerialNumber)
	}

	return signedCert, nil
}

// Verifies that the given certificate matches the given precertificate, assuming
// both are signed with the same signer.
func matchCertWithPrecert(certDER []byte, precert *x509.Certificate) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return cferr.New(cferr.CTError, cferr.CertParsingFailed)
	}

	// Check all fields match between each cert. See
	// https://tools.ietf.org/html/rfc5280#section-4.1
	//
	// XXX: Assume we never put issuerUniqueID, subjectUniqueID, or any tagged field
	// other than [0] (version) and [3] (extensions) into certificates. This version
	// check partially enforces that since new non-extension fields are more likely
	// to be added in a new X509 version (e.g. X509v5) than to the current version
	// (X509v3).
	if cert.Version != 3 {
		return cferr.New(cferr.CTError, cferr.CertIsNotV3)
	}

	if cert.Version != precert.Version {
		return cferr.New(cferr.CTError, cferr.CTMismatchedVersion)
	}
	if cert.SerialNumber.Cmp(precert.SerialNumber) != 0 {
		return cferr.New(cferr.CTError, cferr.CTMismatchedSerialNumber)
	}
	// XXX: The `Signature` field isn't represented in x509.Certificate. Assume that we comply
	// with RFC 5280 and `SignatureAlgorithm` (checked below) matches `Signature`.

	if !bytes.Equal(cert.RawIssuer, precert.RawIssuer) {
		return cferr.New(cferr.CTError, cferr.CTMismatchedIssuer)
	}
	if cert.NotBefore != precert.NotBefore {
		return cferr.New(cferr.CTError, cferr.CTMismatchedNotBefore)
	}
	if cert.NotAfter != precert.NotAfter {
		return cferr.New(cferr.CTError, cferr.CTMismatchedNotAfter)
	}
	if !bytes.Equal(cert.RawSubject, precert.RawSubject) {
		return cferr.New(cferr.CTError, cferr.CTMismatchedSubject)
	}
	if !bytes.Equal(cert.RawSubjectPublicKeyInfo, precert.RawSubjectPublicKeyInfo) {
		return cferr.New(cferr.CTError, cferr.CTMismatchedSubjectPublicKeyInfo)
	}
	// Assume issuerUniqueID is not present; see comment above.
	// Assume subjectUniqueID is not present; see comment above.

	// The extensions must be the same, in the same order, except |cert| may have
	// an SCT list extension and |precert| may have a CT poison extension.
	certExtensions, err := allExtensionsExcept(cert.Extensions, signer.SCTListOID, cferr.MultipleSCTListExtensions)
	if err != nil {
		return err
	}
	precertExtensions, err := allExtensionsExcept(cert.Extensions, signer.CTPoisonOID, cferr.MultiplePoisonExtensions)
	if err != nil {
		return err
	}
	if len(certExtensions) != len(precertExtensions) {
		return cferr.New(cferr.CTError, cferr.CTMismatchedExtensionCount)
	}
	for i, certExt := range certExtensions {
		precertExt := precertExtensions[i]
		if !certExt.Id.Equal(precertExt.Id) {
			return cferr.New(cferr.CTError, cferr.CTMismatchedExtensionID)
		}
		if certExt.Critical != precertExt.Critical {
			return cferr.New(cferr.CTError, cferr.CTMismatchedExtensionCritical)
		}
		if !bytes.Equal(certExt.Value, precertExt.Value) {
			return cferr.New(cferr.CTError, cferr.CTMismatchedExtensionValue)
		}
	}

	if cert.SignatureAlgorithm != precert.SignatureAlgorithm {
		return cferr.New(cferr.CTError, cferr.CTMismatchedSignatureAlgorithm)
	}

	// The signatures are expected to be different, so don't compare them.

	return nil
}

// Info return a populated info.Resp struct or an error.
func (s *Signer) Info(req info.Req) (resp *info.Resp, err error) {
	cert, err := s.Certificate(req.Label, req.Profile)
	if err != nil {
		return
	}

	profile, err := signer.Profile(s, req.Profile)
	if err != nil {
		return
	}

	resp = new(info.Resp)
	if cert.Raw != nil {
		resp.Certificate = string(bytes.TrimSpace(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
	}
	resp.Usage = profile.Usage
	resp.ExpiryString = profile.ExpiryString

	return
}

// SigAlgo returns the RSA signer's signature algorithm.
func (s *Signer) SigAlgo() x509.SignatureAlgorithm {
	return s.sigAlgo
}

// Certificate returns the signer's certificate.
func (s *Signer) Certificate(label, profile string) (*x509.Certificate, error) {
	cert := *s.ca
	return &cert, nil
}

// SetPolicy sets the signer's signature policy.
func (s *Signer) SetPolicy(policy *config.Signing) {
	s.policy = policy
}

// SetDBAccessor sets the signers' cert db accessor
func (s *Signer) SetDBAccessor(dba certdb.Accessor) {
	s.dbAccessor = dba
}

// GetDBAccessor returns the signers' cert db accessor
func (s *Signer) GetDBAccessor() certdb.Accessor {
	return s.dbAccessor
}

// SetReqModifier does nothing for local
func (s *Signer) SetReqModifier(func(*http.Request, []byte)) {
	// noop
}

// Policy returns the signer's policy.
func (s *Signer) Policy() *config.Signing {
	return s.policy
}

func findCTPoisonExtension(cert *x509.Certificate) *pkix.Extension {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(signer.CTPoisonOID) {
			return &ext
		}
	}
	return nil
}

func allExtensionsExcept(input []pkix.Extension, idToExclude asn1.ObjectIdentifier, duplicateError cferr.Reason) ([]pkix.Extension, error) {
	result := []pkix.Extension{}
	found := false
	for _, extension := range input {
		if idToExclude.Equal(extension.Id) {
			if found {
				return nil, cferr.New(cferr.CTError, duplicateError)
			}
			found = true
		} else {
			result = append(result, extension)
		}
	}
	return result, nil
}
