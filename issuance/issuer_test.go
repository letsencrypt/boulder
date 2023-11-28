package issuance

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/linter"
	"github.com/letsencrypt/boulder/test"
)

func defaultProfileConfig() ProfileConfig {
	return ProfileConfig{
		AllowCommonName:     true,
		AllowCTPoison:       true,
		AllowSCTList:        true,
		AllowMustStaple:     true,
		MaxValidityPeriod:   config.Duration{Duration: time.Hour},
		MaxValidityBackdate: config.Duration{Duration: time.Hour},
	}
}

func defaultIssuerConfig() IssuerConfig {
	return IssuerConfig{
		UseForECDSALeaves: true,
		UseForRSALeaves:   true,
		IssuerURL:         "http://issuer-url",
		OCSPURL:           "http://ocsp-url",
	}
}

var issuerCert *Certificate
var issuerSigner *ecdsa.PrivateKey

func TestMain(m *testing.M) {
	tk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cmd.FailOnError(err, "failed to generate test key")
	issuerSigner = tk
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(123),
		BasicConstraintsValid: true,
		IsCA:                  true,
		Subject: pkix.Name{
			CommonName: "big ca",
		},
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	issuer, err := x509.CreateCertificate(rand.Reader, template, template, tk.Public(), tk)
	cmd.FailOnError(err, "failed to generate test issuer")
	cert, err := x509.ParseCertificate(issuer)
	cmd.FailOnError(err, "failed to parse test issuer")
	issuerCert = &Certificate{Certificate: cert}
	os.Exit(m.Run())
}

func TestNewIssuer(t *testing.T) {
	_, err := NewIssuer(
		issuerCert,
		issuerSigner,
		defaultProfile(),
		&linter.Linter{},
		clock.NewFake(),
	)
	test.AssertNotError(t, err, "NewIssuer failed")
}

func TestNewIssuerUnsupportedKeyType(t *testing.T) {
	_, err := NewIssuer(
		&Certificate{
			Certificate: &x509.Certificate{
				PublicKey: &ed25519.PublicKey{},
			},
		},
		&ed25519.PrivateKey{},
		defaultProfile(),
		&linter.Linter{},
		clock.NewFake(),
	)
	test.AssertError(t, err, "NewIssuer didn't fail")
	test.AssertEquals(t, err.Error(), "unsupported issuer key type")
}

func TestNewIssuerNoCertSign(t *testing.T) {
	_, err := NewIssuer(
		&Certificate{
			Certificate: &x509.Certificate{
				PublicKey: &ecdsa.PublicKey{
					Curve: elliptic.P256(),
				},
				KeyUsage: 0,
			},
		},
		issuerSigner,
		defaultProfile(),
		&linter.Linter{},
		clock.NewFake(),
	)
	test.AssertError(t, err, "NewIssuer didn't fail")
	test.AssertEquals(t, err.Error(), "end-entity signing cert does not have keyUsage certSign")
}

func TestNewIssuerNoDigitalSignature(t *testing.T) {
	_, err := NewIssuer(
		&Certificate{
			Certificate: &x509.Certificate{
				PublicKey: &ecdsa.PublicKey{
					Curve: elliptic.P256(),
				},
				KeyUsage: x509.KeyUsageCertSign,
			},
		},
		issuerSigner,
		defaultProfile(),
		&linter.Linter{},
		clock.NewFake(),
	)
	test.AssertError(t, err, "NewIssuer didn't fail")
	test.AssertEquals(t, err.Error(), "end-entity ocsp signing cert does not have keyUsage digitalSignature")
}

func TestNewIssuerOCSPOnly(t *testing.T) {
	p := defaultProfile()
	p.useForRSALeaves = false
	p.useForECDSALeaves = false
	_, err := NewIssuer(
		&Certificate{
			Certificate: &x509.Certificate{
				PublicKey: &ecdsa.PublicKey{
					Curve: elliptic.P256(),
				},
				KeyUsage: x509.KeyUsageDigitalSignature,
			},
		},
		issuerSigner,
		p,
		&linter.Linter{},
		clock.NewFake(),
	)
	test.AssertNotError(t, err, "NewIssuer failed")
}

func TestLoadChain_Valid(t *testing.T) {
	chain, err := LoadChain([]string{
		"../test/test-ca-cross.pem",
		"../test/test-root2.pem",
	})
	test.AssertNotError(t, err, "Should load valid chain")

	expectedIssuer, err := core.LoadCert("../test/test-ca-cross.pem")
	test.AssertNotError(t, err, "Failed to load test issuer")

	chainIssuer := chain[0]
	test.AssertNotNil(t, chainIssuer, "Failed to decode chain PEM")

	test.AssertByteEquals(t, chainIssuer.Raw, expectedIssuer.Raw)
}

func TestLoadChain_TooShort(t *testing.T) {
	_, err := LoadChain([]string{"/path/to/one/cert.pem"})
	test.AssertError(t, err, "Should reject too-short chain")
}

func TestLoadChain_Unloadable(t *testing.T) {
	_, err := LoadChain([]string{
		"does-not-exist.pem",
		"../test/test-root2.pem",
	})
	test.AssertError(t, err, "Should reject unloadable chain")

	_, err = LoadChain([]string{
		"../test/test-ca-cross.pem",
		"does-not-exist.pem",
	})
	test.AssertError(t, err, "Should reject unloadable chain")

	invalidPEMFile, _ := os.CreateTemp("", "invalid.pem")
	err = os.WriteFile(invalidPEMFile.Name(), []byte(""), 0640)
	test.AssertNotError(t, err, "Error writing invalid PEM tmp file")
	_, err = LoadChain([]string{
		invalidPEMFile.Name(),
		"../test/test-root2.pem",
	})
	test.AssertError(t, err, "Should reject unloadable chain")
}

func TestLoadChain_InvalidSig(t *testing.T) {
	_, err := LoadChain([]string{
		"../test/test-root2.pem",
		"../test/test-ca-cross.pem",
	})
	test.AssertError(t, err, "Should reject invalid signature")
	test.Assert(t, strings.Contains(err.Error(), "test-ca-cross.pem"),
		fmt.Sprintf("Expected error to mention filename, got: %s", err))
	test.Assert(t, strings.Contains(err.Error(), "signature from \"CN=happy hacker fake CA\""),
		fmt.Sprintf("Expected error to mention subject, got: %s", err))
}
