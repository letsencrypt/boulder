// +build integration

package integration

import (
	"os"
	"strings"
	"testing"

	ocsp_helper "github.com/letsencrypt/boulder/test/ocsp/helper"
	"golang.org/x/crypto/ocsp"
)

func TestPrecertificateOCSP(t *testing.T) {
	t.Parallel()
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

	// Try to find a precertificate matching the domain from one of the
	// configured ct-test-srv instances.
	cert, err := ctFindRejection([]string{domain})
	if err != nil || cert == nil {
		t.Fatalf("couldn't find rejected precert for %q", domain)
	}

	ocspConfig := ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Good)
	_, err = ocsp_helper.ReqDER(cert.Raw, ocspConfig)
	if err != nil {
		t.Errorf("requesting OCSP for rejected precertificate: %s", err)
	}
}
