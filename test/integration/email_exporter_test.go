//go:build integration

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/eggsampler/acme/v3"

	"github.com/letsencrypt/boulder/test"
)

// randomDomain creates a random domain name for testing.
//
// panics if crypto/rand.Rand.Read fails.
func randomDomain() string {
	var bytes [4]byte
	_, err := rand.Read(bytes[:])
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x.mail.com", bytes[:])
}

// TestProspectsCreatedForNewAccount tests that prospects are dispatched to
// pardot-test-srv by the email-exporter when a new account is created.
func TestProspectsCreatedForNewAccount(t *testing.T) {
	t.Parallel()

	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		t.Skip("Test requires WFE to be configured to use email-exporter")
	}

	domain := randomDomain()

	tests := []struct {
		name            string
		contacts        []string
		expectProspects []string
	}{
		{
			name:            "Single email",
			contacts:        []string{"mailto:example@" + domain},
			expectProspects: []string{"example@" + domain},
		},
		{
			name:            "Multiple emails",
			contacts:        []string{"mailto:example1@" + domain, "mailto:example2@" + domain},
			expectProspects: []string{"example1@" + domain, "example2@" + domain},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, err := acme.NewClient("http://boulder.service.consul:4001/directory")
			if err != nil {
				t.Fatalf("failed to connect to acme directory: %s", err)
			}

			acctKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate account key: %s", err)
			}

			_, err = c.NewAccount(acctKey, false, true, tt.contacts...)
			if err != nil {
				t.Fatalf("failed to create initial account: %s", err)
			}

			// Wait for the prospects to be exported from the email exporter
			// queue to pardot-test-srv.
			time.Sleep(100 * time.Millisecond)

			httpClient := http.DefaultClient
			resp, err := httpClient.Get("http://localhost:9602/query_prospects?" + url.Values{
				"pardot_business_unit_id": []string{"test-business-unit"}}.Encode(),
			)
			test.AssertNotError(t, err, "Failed to query prospects")
			test.AssertEquals(t, resp.StatusCode, http.StatusOK)
			defer resp.Body.Close()

			var got struct {
				Prospects []string `json:"prospects"`
			}
			decoder := json.NewDecoder(resp.Body)
			err = decoder.Decode(&got)
			test.AssertNotError(t, err, "Failed to decode prospects")

			for _, expectEmail := range tt.expectProspects {
				test.AssertSliceContains(t, got.Prospects, expectEmail)
			}
		})
	}
}

// TestProspectsCreatedWhenAccountUpdated tests that prospects are dispatched to
// pardot-test-srv by the email-exporter when an account is updated.
func TestProspectsCreatedWhenAccountUpdated(t *testing.T) {
	t.Parallel()

	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		t.Skip("Test requires WFE to be configured to use email-exporter")
	}

	domain := randomDomain()

	c, err := acme.NewClient("http://boulder.service.consul:4001/directory")
	if err != nil {
		t.Fatalf("failed to connect to acme directory: %s", err)
	}

	acctKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate account key: %s", err)
	}

	acct, err := c.NewAccount(acctKey, false, true)
	if err != nil {
		t.Fatalf("failed to create initial account: %s", err)
	}

	tests := []struct {
		name            string
		contacts        []string
		expectProspects []string
	}{
		{
			name:            "Single email",
			contacts:        []string{"mailto:example@" + domain},
			expectProspects: []string{"example@" + domain},
		},
		{
			name:            "Multiple emails",
			contacts:        []string{"mailto:example1@" + domain, "mailto:example2@" + domain},
			expectProspects: []string{"example1@" + domain, "example2@" + domain},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := c.UpdateAccount(acct, tt.contacts...)
			test.AssertNotError(t, err, "Failed to update account")

			// Wait for the prospects to be exported from the email exporter
			// queue to pardot-test-srv.
			time.Sleep(100 * time.Millisecond)

			httpClient := http.DefaultClient
			resp, err := httpClient.Get("http://localhost:9602/query_prospects?" + url.Values{
				"pardot_business_unit_id": []string{"test-business-unit"}}.Encode(),
			)
			test.AssertNotError(t, err, "Failed to query prospects")
			test.AssertEquals(t, resp.StatusCode, http.StatusOK)
			defer resp.Body.Close()

			var got struct {
				Prospects []string `json:"prospects"`
			}
			decoder := json.NewDecoder(resp.Body)
			err = decoder.Decode(&got)
			test.AssertNotError(t, err, "Failed to decode prospects")

			for _, expectEmail := range tt.expectProspects {
				test.AssertSliceContains(t, got.Prospects, expectEmail)
			}
		})
	}
}
