// +build integration

package integration

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	ocsp_helper "github.com/letsencrypt/boulder/test/ocsp/helper"
)

func TestPrecertificateOCSP(t *testing.T) {
	// This test is gated on the PrecertificateOCSP feature flag.
	if !strings.Contains(os.Getenv("BOULDER_CONFIG_DIR", "test/config-next")) {
		return
	}
	domain := random_domain()
	for _, port := range []int{4500, 4501, 4510, 4511} {
		url := fmt.Sprintf("http://boulder:%d/add-reject-host", port)
		body := []byte(fmt.Sprintf(`{"host": "%s"}`, domain))
		resp, err := http.Post(url, "", bytes.NewBuffer(body))
		if err != nil {
			t.Fatalf("adding reject host: %s", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("adding reject host: %d", resp.StatusCode)
		}
		resp.Body.Close()
	}

	os.Setenv("DIRECTORY", "http://boulder:4001/directory")
	_, err := authAndIssue([]string{domain})
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

	resp, err := http.Get("http://boulder:4500/get-rejections")
	if err != nil {
		t.Fatalf("getting rejections: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("getting rejections: status %d", resp.StatusCode)
	}
	var rejections []string
	err = json.NewDecoder(resp.Body).Decode(&rejections)
	if err != nil {
		t.Fatalf("parsing rejections: %s", err)
	}

	for _, r := range rejections {
		rejectedCertBytes, err := base64.StdEncoding.DecodeString(r)
		if err != nil {
			t.Fatalf("decoding rejected cert: %s", err)
		}
		_, err = ocsp_helper.ReqDER(rejectedCertBytes)
		if err != nil {
			t.Errorf("requesting OCSP for rejected precertificate: %s", err)
		}
	}
}
