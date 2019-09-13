// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// ctAddRejectHost adds a domain to all of the CT test server's reject-host
// lists. If this fails the test is aborted with a fatal error.
func ctAddRejectHost(t *testing.T, domain string) {
	for _, port := range []int{4500, 4501, 4510, 4511} {
		url := fmt.Sprintf("http://boulder:%d/add-reject-host", port)
		body := []byte(fmt.Sprintf(`{"host": %q}`, domain))
		resp, err := http.Post(url, "", bytes.NewBuffer(body))
		if err != nil {
			t.Fatalf("adding reject host: %s", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("adding reject host: %d", resp.StatusCode)
		}
		resp.Body.Close()
	}
}

// ctGetRejections returns a slice of base64 encoded certificates that were
// rejected by the CT test server at the specified port. If this fails the test
// is aborted with a fatal error.
func ctGetRejections(t *testing.T, port int) []string {
	url := fmt.Sprintf("http://boulder:%d/get-rejections", port)
	resp, err := http.Get(url)
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
	return rejections
}
