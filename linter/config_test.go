package linter

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/linter/lints/cpcps"
)

// testCert generates a minimal self-signed certificate with the given CN.
func testCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating test key: %s", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("creating test certificate: %s", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing test certificate: %s", err)
	}
	return cert
}

func TestLoadConfigFile(t *testing.T) {
	t.Parallel()

	cfg, err := LoadConfigFile("")
	if err != nil {
		t.Errorf("got error %q for empty path, want nil", err)
	}
	if cfg.toml != "" {
		t.Errorf("got non-empty config %q for empty path", cfg.toml)
	}

	dir := t.TempDir()

	good := path.Join(dir, "good.toml")
	err = os.WriteFile(good, []byte("[w_subject_common_name_included]\nsomething = true\n"), 0644)
	if err != nil {
		t.Fatalf("writing config file: %s", err)
	}
	_, err = LoadConfigFile(good)
	if err != nil {
		t.Errorf("got error %q for valid config file, want nil", err)
	}

	garbage := path.Join(dir, "garbage.toml")
	err = os.WriteFile(garbage, []byte("this is not toml"), 0644)
	if err != nil {
		t.Fatalf("writing config file: %s", err)
	}
	_, err = LoadConfigFile(garbage)
	if err == nil {
		t.Error("got nil error for invalid config file, want error")
	}

	// Config files may not set the shared keys read by the CP/CPS profile
	// lints: their configuration is derived from the issuer certificate.
	// Other keys in the shared stanza are permitted.
	reserved := path.Join(dir, "reserved.toml")
	err = os.WriteFile(reserved, []byte("[Global]\nissuer_certificate = \"bogus\"\n"), 0644)
	if err != nil {
		t.Fatalf("writing config file: %s", err)
	}
	_, err = LoadConfigFile(reserved)
	if err == nil || !strings.Contains(err.Error(), "must not set") {
		t.Errorf("got %v for config file with reserved key, want rejection", err)
	}

	otherGlobal := path.Join(dir, "other-global.toml")
	err = os.WriteFile(otherGlobal, []byte("[Global]\nsomething_else = true\n"), 0644)
	if err != nil {
		t.Fatalf("writing config file: %s", err)
	}
	_, err = LoadConfigFile(otherGlobal)
	if err != nil {
		t.Errorf("got error %q for config file with unrelated shared-stanza key, want nil", err)
	}

	_, err = LoadConfigFile(path.Join(dir, "does-not-exist.toml"))
	if err == nil {
		t.Error("got nil error for nonexistent config file, want error")
	}
}

// TestConfigDerivation exercises the whole layering path: a config file
// loaded from disk, augmented with an issuer and an existing certificate,
// built into a single zlint Configuration in which all three are visible.
func TestConfigDerivation(t *testing.T) {
	t.Parallel()

	filePath := path.Join(t.TempDir(), "zlint.toml")
	err := os.WriteFile(filePath, []byte("[w_subject_common_name_included]\nsomething = true\n"), 0644)
	if err != nil {
		t.Fatalf("writing config file: %s", err)
	}
	config, err := LoadConfigFile(filePath)
	if err != nil {
		t.Fatalf("loading config file: %s", err)
	}

	issuer := testCert(t, "issuer")
	config, err = config.WithIssuer(issuer)
	if err != nil {
		t.Fatalf("adding issuer to config: %s", err)
	}

	existing := testCert(t, "existing")
	config, err = config.WithExisting(existing)
	if err != nil {
		t.Fatalf("adding existing certificate to config: %s", err)
	}

	merged, err := config.build()
	if err != nil {
		t.Fatalf("building lint configuration: %s", err)
	}

	var gotCross struct {
		IssuerCertificatePEM   string `toml:"issuer_certificate"`
		ExistingCertificatePEM string `toml:"existing_certificate"`
	}
	err = merged.Configure(&gotCross, cpcps.GlobalConfigNamespace)
	if err != nil {
		t.Fatalf("deserializing issuer lint configuration: %s", err)
	}

	issuerBlock, _ := pem.Decode([]byte(gotCross.IssuerCertificatePEM))
	if issuerBlock == nil {
		t.Fatal("issuer_certificate did not round-trip as PEM")
	}
	if !issuer.Equal(mustParse(t, issuerBlock.Bytes)) {
		t.Error("issuer_certificate does not match the configured issuer")
	}

	existingBlock, _ := pem.Decode([]byte(gotCross.ExistingCertificatePEM))
	if existingBlock == nil {
		t.Fatal("existing_certificate did not round-trip as PEM")
	}
	if !existing.Equal(mustParse(t, existingBlock.Bytes)) {
		t.Error("existing_certificate does not match the configured existing certificate")
	}

	var gotFile struct {
		Something bool `toml:"something"`
	}
	err = merged.Configure(&gotFile, "w_subject_common_name_included")
	if err != nil {
		t.Fatalf("deserializing file lint configuration: %s", err)
	}
	if !gotFile.Something {
		t.Error("config-file section is not visible in the merged configuration")
	}
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %s", err)
	}
	return cert
}
