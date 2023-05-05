package notmain

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/test"
)

func TestLoadChain_Valid(t *testing.T) {
	issuer, chainPEM, err := loadChain([]string{
		"../../test/test-ca-cross.pem",
		"../../test/test-root2.pem",
	})
	test.AssertNotError(t, err, "Should load valid chain")

	expectedIssuer, err := core.LoadCert("../../test/test-ca-cross.pem")
	test.AssertNotError(t, err, "Failed to load test issuer")

	chainIssuerPEM, rest := pem.Decode(chainPEM)
	test.AssertNotNil(t, chainIssuerPEM, "Failed to decode chain PEM")
	parsedIssuer, err := x509.ParseCertificate(chainIssuerPEM.Bytes)
	test.AssertNotError(t, err, "Failed to parse chain PEM")

	// The three versions of the intermediate (the one loaded by us, the one
	// returned by loadChain, and the one parsed from the chain) should be equal.
	test.AssertByteEquals(t, issuer.Raw, expectedIssuer.Raw)
	test.AssertByteEquals(t, parsedIssuer.Raw, expectedIssuer.Raw)

	// The chain should contain nothing else.
	rootIssuerPEM, _ := pem.Decode(rest)
	if rootIssuerPEM != nil {
		t.Error("Expected chain PEM to contain one cert and nothing else")
	}
}

func TestLoadChain_TooShort(t *testing.T) {
	_, _, err := loadChain([]string{"/path/to/one/cert.pem"})
	test.AssertError(t, err, "Should reject too-short chain")
}

func TestLoadChain_Unloadable(t *testing.T) {
	_, _, err := loadChain([]string{
		"does-not-exist.pem",
		"../../test/test-root2.pem",
	})
	test.AssertError(t, err, "Should reject unloadable chain")

	_, _, err = loadChain([]string{
		"../../test/test-ca-cross.pem",
		"does-not-exist.pem",
	})
	test.AssertError(t, err, "Should reject unloadable chain")

	invalidPEMFile, _ := os.CreateTemp("", "invalid.pem")
	err = os.WriteFile(invalidPEMFile.Name(), []byte(""), 0640)
	test.AssertNotError(t, err, "Error writing invalid PEM tmp file")
	_, _, err = loadChain([]string{
		invalidPEMFile.Name(),
		"../../test/test-root2.pem",
	})
	test.AssertError(t, err, "Should reject unloadable chain")
}

func TestLoadChain_InvalidSig(t *testing.T) {
	_, _, err := loadChain([]string{
		"../../test/test-root2.pem",
		"../../test/test-ca-cross.pem",
	})
	test.AssertError(t, err, "Should reject invalid signature")
}

func TestLoadChain_NoRoot(t *testing.T) {
	// TODO(#5251): Implement this when we have a hierarchy which includes two
	// CA certs, neither of which is a root.
}
