package main

import (
	"crypto/mldsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/privatekey"
)

// goodKeyfileConfig returns a keyfileConfig which passes validation, with its
// outputs in dir.
func goodKeyfileConfig(dir string) keyfileConfig {
	var config keyfileConfig
	config.CeremonyType = "staging-mldsa-keyfile-no-hsm"
	config.Key = keyGenConfig{Type: "mldsa", MLDSAParameterSet: "ML-DSA-44"}
	config.Outputs.PublicKeyPath = filepath.Join(dir, "mtca.pubkey.pem")
	config.Outputs.PrivateKeyPath = filepath.Join(dir, "mtca.key.pem")
	return config
}

func TestKeyfileConfigValidate(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing.pem")
	err := os.WriteFile(existing, []byte("hi"), 0600)
	if err != nil {
		t.Fatalf("writing existing file: %s", err)
	}

	testCases := []struct {
		name    string
		modify  func(*keyfileConfig)
		wantErr string
	}{
		{
			name:   "good config",
			modify: func(*keyfileConfig) {},
		},
		{
			name:    "no key.type",
			modify:  func(c *keyfileConfig) { c.Key = keyGenConfig{} },
			wantErr: "key.type is required",
		},
		{
			name:    "bad key.mldsa-parameter-set",
			modify:  func(c *keyfileConfig) { c.Key.MLDSAParameterSet = "ML-DSA-1337" },
			wantErr: "key.mldsa-parameter-set can only be",
		},
		{
			name:    "rsa key",
			modify:  func(c *keyfileConfig) { c.Key = keyGenConfig{Type: "rsa", RSAModLength: 2048} },
			wantErr: "must only be used for ML-DSA-44 keys",
		},
		{
			name:    "ecdsa key",
			modify:  func(c *keyfileConfig) { c.Key = keyGenConfig{Type: "ecdsa", ECDSACurve: "P-256"} },
			wantErr: "must only be used for ML-DSA-44 keys",
		},
		{
			name:    "ML-DSA-87 key",
			modify:  func(c *keyfileConfig) { c.Key.MLDSAParameterSet = "ML-DSA-87" },
			wantErr: "must only be used for ML-DSA-44 keys",
		},
		{
			name:    "no outputs.public-key-path",
			modify:  func(c *keyfileConfig) { c.Outputs.PublicKeyPath = "" },
			wantErr: "outputs.public-key-path is required",
		},
		{
			name:    "no outputs.private-key-path",
			modify:  func(c *keyfileConfig) { c.Outputs.PrivateKeyPath = "" },
			wantErr: "outputs.private-key-path is required",
		},
		{
			name:    "outputs.public-key-path already exists",
			modify:  func(c *keyfileConfig) { c.Outputs.PublicKeyPath = existing },
			wantErr: fmt.Sprintf("outputs.public-key-path is %q, which already exists", existing),
		},
		{
			name:    "outputs.private-key-path already exists",
			modify:  func(c *keyfileConfig) { c.Outputs.PrivateKeyPath = existing },
			wantErr: fmt.Sprintf("outputs.private-key-path is %q, which already exists", existing),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := goodKeyfileConfig(dir)
			tc.modify(&config)

			err := config.validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validate() = %v, want success", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validate() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestKeyfileCeremony(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "mtca.pubkey.pem")
	privPath := filepath.Join(dir, "mtca.key.pem")
	config := fmt.Appendf(nil, `ceremony-type: staging-mldsa-keyfile-no-hsm
key:
  type: mldsa
  mldsa-parameter-set: ML-DSA-44
outputs:
  public-key-path: %s
  private-key-path: %s
`, pubPath, privPath)

	err := keyfileCeremony(config)
	if err != nil {
		t.Fatalf("keyfileCeremony() = %v, want success", err)
	}

	// The private key file must not be accessible to anyone but its owner.
	info, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("stat private key file: %s", err)
	}
	if info.Mode().Perm()&0077 != 0 {
		t.Errorf("private key file has mode %s, want no group or other permissions", info.Mode().Perm())
	}

	privPEM, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("reading private key file: %s", err)
	}
	block, rest := pem.Decode(privPEM)
	if block == nil {
		t.Fatalf("no PEM block found in private key file")
	}
	if block.Type != "PRIVATE KEY" {
		t.Errorf("private key file has PEM type %q, want PRIVATE KEY", block.Type)
	}
	if len(rest) != 0 {
		t.Errorf("private key file has %d bytes of trailing data, want none", len(rest))
	}
	parsedPriv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parsing private key: %s", err)
	}
	priv, ok := parsedPriv.(*mldsa.PrivateKey)
	if !ok {
		t.Fatalf("private key file contains a %T, want *mldsa.PrivateKey", parsedPriv)
	}
	if priv.PublicKey().Parameters() != mldsa.MLDSA44() {
		t.Errorf("private key has parameter set %s, want ML-DSA-44", priv.PublicKey().Parameters())
	}

	pubPEM, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("reading public key file: %s", err)
	}
	block, rest = pem.Decode(pubPEM)
	if block == nil {
		t.Fatalf("no PEM block found in public key file")
	}
	if block.Type != "PUBLIC KEY" {
		t.Errorf("public key file has PEM type %q, want PUBLIC KEY", block.Type)
	}
	if len(rest) != 0 {
		t.Errorf("public key file has %d bytes of trailing data, want none", len(rest))
	}
	parsedPub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parsing public key: %s", err)
	}
	if !priv.PublicKey().Equal(parsedPub) {
		t.Errorf("public key file doesn't match private key file")
	}

	// Boulder's file-based issuers load their keys with privatekey.Load, which
	// also checks that the private key's signatures verify with its public key.
	_, loadedPub, err := privatekey.Load(privPath)
	if err != nil {
		t.Fatalf("privatekey.Load() = %v, want success", err)
	}
	if !priv.PublicKey().Equal(loadedPub) {
		t.Errorf("privatekey.Load() returned a different public key than the private key file contains")
	}
}

func TestKeyfileCeremonyBadConfig(t *testing.T) {
	// Each config is formatted with a fresh temporary directory as its only
	// argument.
	testCases := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name: "pkcs11 section",
			config: `ceremony-type: staging-mldsa-keyfile-no-hsm
pkcs11:
  module: /usr/lib/softhsm/libsofthsm2.so
  store-key-in-slot: 0
  store-key-with-label: mtca
key:
  type: mldsa
  mldsa-parameter-set: ML-DSA-44
outputs:
  public-key-path: %[1]s/mtca.pubkey.pem
  private-key-path: %[1]s/mtca.key.pem
`,
			wantErr: "failed to parse config",
		},
		{
			name: "ecdsa key",
			config: `ceremony-type: staging-mldsa-keyfile-no-hsm
key:
  type: ecdsa
  ecdsa-curve: P-256
outputs:
  public-key-path: %[1]s/mtca.pubkey.pem
  private-key-path: %[1]s/mtca.key.pem
`,
			wantErr: "failed to validate config",
		},
		{
			name: "ML-DSA-87 key",
			config: `ceremony-type: staging-mldsa-keyfile-no-hsm
key:
  type: mldsa
  mldsa-parameter-set: ML-DSA-87
outputs:
  public-key-path: %[1]s/mtca.pubkey.pem
  private-key-path: %[1]s/mtca.key.pem
`,
			wantErr: "failed to validate config",
		},
		{
			name: "private-key-path in a nonexistent directory",
			config: `ceremony-type: staging-mldsa-keyfile-no-hsm
key:
  type: mldsa
  mldsa-parameter-set: ML-DSA-44
outputs:
  public-key-path: %[1]s/mtca.pubkey.pem
  private-key-path: %[1]s/missing/mtca.key.pem
`,
			wantErr: "no such file or directory",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()

			err := keyfileCeremony(fmt.Appendf(nil, tc.config, dir))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("keyfileCeremony() = %v, want error containing %q", err, tc.wantErr)
			}

			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatalf("reading output directory: %s", err)
			}
			for _, e := range entries {
				t.Errorf("keyfileCeremony() failed but wrote %q", e.Name())
			}
		})
	}
}

func TestKeyfileCeremonyExistingPrivateKey(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "mtca.pubkey.pem")
	privPath := filepath.Join(dir, "mtca.key.pem")
	original := []byte("an existing private key")
	err := os.WriteFile(privPath, original, 0600)
	if err != nil {
		t.Fatalf("writing existing private key file: %s", err)
	}
	config := fmt.Appendf(nil, `ceremony-type: staging-mldsa-keyfile-no-hsm
key:
  type: mldsa
  mldsa-parameter-set: ML-DSA-44
outputs:
  public-key-path: %s
  private-key-path: %s
`, pubPath, privPath)

	err = keyfileCeremony(config)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("keyfileCeremony() = %v, want error containing %q", err, "already exists")
	}

	got, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("reading private key file: %s", err)
	}
	if string(got) != string(original) {
		t.Errorf("keyfileCeremony() overwrote the existing private key file")
	}
	_, err = os.Stat(pubPath)
	if !os.IsNotExist(err) {
		t.Errorf("keyfileCeremony() wrote a public key file despite failing: stat error %v", err)
	}
}
