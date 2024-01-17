package issuance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/jmhodges/clock"
	"golang.org/x/crypto/ocsp"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/linter"
	"github.com/letsencrypt/boulder/privatekey"
	"github.com/letsencrypt/pkcs11key/v4"
)

// ----- Name ID -----

// NameID is a statistically-unique small ID which can be computed from
// both CA and end-entity certs to link them together into a validation chain.
// It is computed as a truncated hash over the issuer Subject Name bytes, or
// over the end-entity's Issuer Name bytes, which are required to be equal.
type NameID int64

// SubjectNameID returns the NameID (a truncated hash over the raw bytes of a
// Distinguished Name) of this issuer certificate's Subject. Useful for storing
// as a lookup key in contexts that don't expect hash collisions.
func SubjectNameID(ic *Certificate) NameID {
	return truncatedHash(ic.RawSubject)
}

// IssuerNameID returns the IssuerNameID (a truncated hash over the raw bytes
// of the Issuer Distinguished Name) of the given end-entity certificate.
// Useful for performing lookups in contexts that don't expect hash collisions.
func IssuerNameID(ee *x509.Certificate) NameID {
	return truncatedHash(ee.RawIssuer)
}

// ResponderNameID returns the NameID (a truncated hash over the raw
// bytes of the Responder Distinguished Name) of the given OCSP Response.
// As per the OCSP spec, it is technically possible for this field to not be
// populated: the OCSP Response can instead contain a SHA-1 hash of the Issuer
// Public Key as the Responder ID. However, all OCSP responses that we produce
// contain it, because the Go stdlib always includes it.
func ResponderNameID(resp *ocsp.Response) NameID {
	return truncatedHash(resp.RawResponderName)
}

// truncatedHash computes a truncated SHA1 hash across arbitrary bytes. Uses
// SHA1 because that is the algorithm most commonly used in OCSP requests.
// PURPOSEFULLY NOT EXPORTED. Exists only to ensure that the implementations of
// SubjectNameID(), IssuerNameID(), and ResponderNameID never diverge. Use those
// instead.
func truncatedHash(name []byte) NameID {
	h := crypto.SHA1.New()
	h.Write(name)
	s := h.Sum(nil)
	return NameID(big.NewInt(0).SetBytes(s[:7]).Int64())
}

// ----- Issuer Certificates -----

// Certificate embeds an *x509.Certificate and represents the added semantics
// that this certificate is a CA certificate.
type Certificate struct {
	*x509.Certificate
	// nameID is stored here simply for the sake of precomputation.
	nameID NameID
}

// NameID is equivalent to SubjectNameID(ic), but faster because it is
// precomputed.
func (ic *Certificate) NameID() NameID {
	return ic.nameID
}

// NewCertificate wraps an in-memory cert in an issuance.Certificate, marking it
// as an issuer cert. It may fail if the certificate does not contain the
// attributes expected of an issuer certificate.
func NewCertificate(ic *x509.Certificate) (*Certificate, error) {
	if !ic.IsCA {
		return nil, errors.New("certificate is not a CA certificate")
	}

	res := Certificate{ic, 0}
	res.nameID = SubjectNameID(&res)
	return &res, nil
}

func LoadCertificate(path string) (*Certificate, error) {
	cert, err := core.LoadCert(path)
	if err != nil {
		return nil, err
	}
	return NewCertificate(cert)
}

// LoadChain takes a list of filenames containing pem-formatted certificates,
// and returns a chain representing all of those certificates in order. It
// ensures that the resulting chain is valid. The final file is expected to be
// a root certificate, which the chain will be verified against, but which will
// not be included in the resulting chain.
func LoadChain(certFiles []string) ([]*Certificate, error) {
	if len(certFiles) < 2 {
		return nil, errors.New(
			"each chain must have at least two certificates: an intermediate and a root")
	}

	// Pre-load all the certificates to make validation easier.
	certs := make([]*Certificate, len(certFiles))
	var err error
	for i := 0; i < len(certFiles); i++ {
		certs[i], err = LoadCertificate(certFiles[i])
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate %q: %w", certFiles[i], err)
		}
	}

	// Iterate over all certs except for the last, checking that their signature
	// comes from the next cert in the list.
	chain := make([]*Certificate, len(certFiles)-1)
	for i := 0; i < len(certs)-1; i++ {
		err = certs[i].CheckSignatureFrom(certs[i+1].Certificate)
		if err != nil {
			return nil, fmt.Errorf("failed to verify signature from %q to %q (%q to %q): %w",
				certs[i+1].Subject, certs[i].Subject, certFiles[i+1], certFiles[i], err)
		}
		chain[i] = certs[i]
	}

	// Verify that the last cert is self-signed.
	lastCert := certs[len(certs)-1]
	err = lastCert.CheckSignatureFrom(lastCert.Certificate)
	if err != nil {
		return nil, fmt.Errorf(
			"final cert in chain (%q; %q) must be self-signed (used only for validation): %w",
			lastCert.Subject, certFiles[len(certFiles)-1], err)
	}

	return chain, nil
}

// ----- Issuers with Signers -----

// IssuerConfig describes the constraints on and URLs used by a single issuer.
type IssuerConfig struct {
	UseForRSALeaves   bool
	UseForECDSALeaves bool

	IssuerURL string `validate:"required,url"`
	OCSPURL   string `validate:"required,url"`
	CRLURL    string `validate:"omitempty,url"`

	Location IssuerLoc
}

// IssuerLoc describes the on-disk location and parameters that an issuer
// should use to retrieve its certificate and private key.
// Only one of File, ConfigFile, or PKCS11 should be set.
type IssuerLoc struct {
	// A file from which a private key will be read and parsed.
	File string `validate:"required_without_all=ConfigFile PKCS11"`
	// A file from which a pkcs11key.Config will be read and parsed, if File is not set.
	ConfigFile string `validate:"required_without_all=PKCS11 File"`
	// An in-memory pkcs11key.Config, which will be used if ConfigFile is not set.
	PKCS11 *pkcs11key.Config `validate:"required_without_all=ConfigFile File"`
	// A file from which a certificate will be read and parsed.
	CertFile string `validate:"required"`
	// Number of sessions to open with the HSM. For maximum performance,
	// this should be equal to the number of cores in the HSM. Defaults to 1.
	NumSessions int
}

// Issuer is capable of issuing new certificates
// TODO(#5086): make Cert and Signer private when they're no longer needed by ca.internalIssuer
type Issuer struct {
	Cert    *Certificate
	Signer  crypto.Signer
	Profile *Profile
	Linter  *linter.Linter
	Clk     clock.Clock
}

// NewIssuer constructs an Issuer on the heap, verifying that the profile
// is well-formed.
func NewIssuer(cert *Certificate, signer crypto.Signer, profile *Profile, linter *linter.Linter, clk clock.Clock) (*Issuer, error) {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		profile.sigAlg = x509.SHA256WithRSA
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			profile.sigAlg = x509.ECDSAWithSHA256
		case elliptic.P384():
			profile.sigAlg = x509.ECDSAWithSHA384
		default:
			return nil, fmt.Errorf("unsupported ECDSA curve: %s", k.Curve.Params().Name)
		}
	default:
		return nil, errors.New("unsupported issuer key type")
	}

	if profile.useForRSALeaves || profile.useForECDSALeaves {
		if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.New("end-entity signing cert does not have keyUsage certSign")
		}
	}
	// TODO(#5086): Only do this check for ocsp-issuing issuers.
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, errors.New("end-entity ocsp signing cert does not have keyUsage digitalSignature")
	}

	i := &Issuer{
		Cert:    cert,
		Signer:  signer,
		Profile: profile,
		Linter:  linter,
		Clk:     clk,
	}
	return i, nil
}

// Algs provides the list of leaf certificate public key algorithms for which
// this issuer is willing to issue. This is not necessarily the same as the
// public key algorithm or signature algorithm in this issuer's own cert.
func (i *Issuer) Algs() []x509.PublicKeyAlgorithm {
	var algs []x509.PublicKeyAlgorithm
	if i.Profile.useForRSALeaves {
		algs = append(algs, x509.RSA)
	}
	if i.Profile.useForECDSALeaves {
		algs = append(algs, x509.ECDSA)
	}
	return algs
}

// Name provides the Common Name specified in the issuer's certificate.
func (i *Issuer) Name() string {
	return i.Cert.Subject.CommonName
}

// NameID provides the NameID of the issuer's certificate.
func (i *Issuer) NameID() NameID {
	return i.Cert.NameID()
}

// LoadIssuer loads a signer (private key) and certificate from the locations specified.
func LoadIssuer(location IssuerLoc) (*Certificate, crypto.Signer, error) {
	issuerCert, err := LoadCertificate(location.CertFile)
	if err != nil {
		return nil, nil, err
	}

	signer, err := loadSigner(location, issuerCert)
	if err != nil {
		return nil, nil, err
	}

	if !core.KeyDigestEquals(signer.Public(), issuerCert.PublicKey) {
		return nil, nil, fmt.Errorf("Issuer key did not match issuer cert %s", location.CertFile)
	}
	return issuerCert, signer, err
}

func loadSigner(location IssuerLoc, cert *Certificate) (crypto.Signer, error) {
	if location.File != "" {
		signer, _, err := privatekey.Load(location.File)
		if err != nil {
			return nil, err
		}
		return signer, nil
	}

	var pkcs11Config *pkcs11key.Config
	if location.ConfigFile != "" {
		contents, err := os.ReadFile(location.ConfigFile)
		if err != nil {
			return nil, err
		}
		pkcs11Config = new(pkcs11key.Config)
		err = json.Unmarshal(contents, pkcs11Config)
		if err != nil {
			return nil, err
		}
	} else {
		pkcs11Config = location.PKCS11
	}

	if pkcs11Config.Module == "" ||
		pkcs11Config.TokenLabel == "" ||
		pkcs11Config.PIN == "" {
		return nil, fmt.Errorf("missing a field in pkcs11Config %#v", pkcs11Config)
	}

	numSessions := location.NumSessions
	if numSessions <= 0 {
		numSessions = 1
	}

	return pkcs11key.NewPool(numSessions, pkcs11Config.Module,
		pkcs11Config.TokenLabel, pkcs11Config.PIN, cert.PublicKey)
}
