package main

import (
	"testing"

	"github.com/letsencrypt/boulder/cmd"
)

func TestLoadIssuerSuccess(t *testing.T) {
	signer, cert, err := loadIssuer(cmd.IssuerConfig{
		File:     "../../test/test-ca.key",
		CertFile: "../../test/test-ca2.pem",
	})
	if err != nil {
		t.Fatal(err)
	}
	if signer == nil {
		t.Fatal("loadIssuer returned nil signer")
	}
	if cert == nil {
		t.Fatal("loadIssuer returned nil cert")
	}
}

func TestLoadIssuerBadKey(t *testing.T) {
	_, _, err := loadIssuer(cmd.IssuerConfig{
		File:     "/dev/null",
		CertFile: "../../test/test-ca2.pem",
	})
	if err == nil {
		t.Fatal("loadIssuer succeeded when loading key from /dev/null")
	}
}

func TestLoadIssuerBadCert(t *testing.T) {
	_, _, err := loadIssuer(cmd.IssuerConfig{
		File:     "../../test/test-ca.key",
		CertFile: "/dev/null",
	})
	if err == nil {
		t.Fatal("loadIssuer succeeded when loading key from /dev/null")
	}
}
