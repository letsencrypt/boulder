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

// TestContactsSentForNewAccount tests that contacts are dispatched to
// pardot-test-srv by the email-exporter when a new account is created.
func TestContactsSentForNewAccount(t *testing.T) {
	t.Parallel()

	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		t.Skip("Test requires WFE to be configured to use email-exporter")
	}

	domain := randomDomain()

	tests := []struct {
		name           string
		contacts       []string
		expectContacts []string
	}{
		{
			name:           "Single email",
			contacts:       []string{"mailto:example@" + domain},
			expectContacts: []string{"example@" + domain},
		},
		{
			name:           "Multiple emails",
			contacts:       []string{"mailto:example1@" + domain, "mailto:example2@" + domain},
			expectContacts: []string{"example1@" + domain, "example2@" + domain},
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

			// Wait for the contacts to be exported from the email exporter
			// queue to pardot-test-srv.
			time.Sleep(1 * time.Second)

			httpClient := http.DefaultClient
			resp, err := httpClient.Get("http://localhost:9602/contacts?" + url.Values{
				"pardot_business_unit_id": []string{"test-business-unit"}}.Encode(),
			)
			test.AssertNotError(t, err, "Failed to query contacts")
			test.AssertEquals(t, resp.StatusCode, http.StatusOK)
			defer resp.Body.Close()

			var got struct {
				Contacts []string `json:"contacts"`
			}
			decoder := json.NewDecoder(resp.Body)
			err = decoder.Decode(&got)
			test.AssertNotError(t, err, "Failed to decode contacts")

			for _, expectEmail := range tt.expectContacts {
				test.AssertSliceContains(t, got.Contacts, expectEmail)
			}
		})
	}
}

// TestContactsSentWhenAccountUpdated tests that contacts are dispatched to
// pardot-test-srv by the email-exporter when an account is updated.
func TestContactsSentWhenAccountUpdated(t *testing.T) {
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
		name           string
		contacts       []string
		expectContacts []string
	}{
		{
			name:           "Single email",
			contacts:       []string{"mailto:example@" + domain},
			expectContacts: []string{"example@" + domain},
		},
		{
			name:           "Multiple emails",
			contacts:       []string{"mailto:example1@" + domain, "mailto:example2@" + domain},
			expectContacts: []string{"example1@" + domain, "example2@" + domain},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := c.UpdateAccount(acct, tt.contacts...)
			test.AssertNotError(t, err, "Failed to update account")

			// Wait for the contacts to be exported from the email exporter
			// queue to pardot-test-srv.
			time.Sleep(1 * time.Second)

			httpClient := http.DefaultClient
			resp, err := httpClient.Get("http://localhost:9602/contacts?" + url.Values{
				"pardot_business_unit_id": []string{"test-business-unit"}}.Encode(),
			)
			test.AssertNotError(t, err, "Failed to query contacts")
			test.AssertEquals(t, resp.StatusCode, http.StatusOK)
			defer resp.Body.Close()

			var got struct {
				Contacts []string `json:"contacts"`
			}
			decoder := json.NewDecoder(resp.Body)
			err = decoder.Decode(&got)
			test.AssertNotError(t, err, "Failed to decode contacts")

			for _, expectEmail := range tt.expectContacts {
				test.AssertSliceContains(t, got.Contacts, expectEmail)
			}
		})
	}
}
