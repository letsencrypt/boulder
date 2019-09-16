// +build integration

package integration

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"

	ocsp_helper "github.com/letsencrypt/boulder/test/ocsp/helper"
	"golang.org/x/crypto/ocsp"
)

func TestPrecertificateOCSP(t *testing.T) {
	// This test is gated on the PrecertificateOCSP feature flag.
	if !strings.Contains(os.Getenv("BOULDER_CONFIG_DIR"), "test/config-next") {
		return
	}
	domain := random_domain()
	err := ctAddRejectHost(domain)
	if err != nil {
		t.Fatalf("adding ct-test-srv reject host: %s", err)
	}

	os.Setenv("DIRECTORY", "http://boulder:4001/directory")
	_, err = authAndIssue(nil, nil, []string{domain})
	if err != nil {
		if strings.Contains(err.Error(), "urn:ietf:params:acme:error:serverInternal") &&
			strings.Contains(err.Error(), "SCT embedding") {
		} else {
			t.Fatal(err)
		}
	}
	if err == nil {
		t.Fatal("expected error issuing for domain rejected by CT servers; got none")
	}

	rejections, err := ctGetRejections(4500)
	if err != nil {
		t.Fatalf("getting ct-test-srv rejections: %s", err)
	}
	for _, r := range rejections {
		rejectedCertBytes, err := base64.StdEncoding.DecodeString(r)
		if err != nil {
			t.Fatalf("decoding rejected cert: %s", err)
		}
		_, err = ocsp_helper.ReqDER(rejectedCertBytes, ocsp.Good)
		if err != nil {
			t.Errorf("requesting OCSP for rejected precertificate: %s", err)
		}
	}
}
