//go:build integration

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/eggsampler/acme/v3"

	"github.com/letsencrypt/boulder/test"
)

// randomDomain creates a random domain name for testing.
func randomDomain(t *testing.T) string {
	t.Helper()

	var bytes [4]byte
	_, err := rand.Read(bytes[:])
	if err != nil {
		test.AssertNotError(t, err, "Failed to generate random domain")
	}
	return fmt.Sprintf("%x.mail.com", bytes[:])
}

// getCreatedContacts queries the pardot-test-srv for the list of created
// contacts.
func getCreatedContacts(t *testing.T) []string {
	t.Helper()

	httpClient := http.DefaultClient
	resp, err := httpClient.Get("http://localhost:9602/contacts")
	test.AssertNotError(t, err, "Failed to query contacts")
	test.AssertEquals(t, resp.StatusCode, http.StatusOK)
	defer resp.Body.Close()

	var got struct {
		Contacts []string `json:"contacts"`
	}
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&got)
	test.AssertNotError(t, err, "Failed to decode contacts")
	return got.Contacts
}

// assertAllContactsReceived waits for the expected contacts to be received by
// pardot-test-srv. Retries every 50ms for up to 2 seconds and fails if the
// expected contacts are not received.
func assertAllContactsReceived(t *testing.T, expect []string) {
	t.Helper()

	for attempt := range 20 {
		if attempt > 0 {
			time.Sleep(50 * time.Millisecond)
		}
		got := getCreatedContacts(t)

		allFound := true
		for _, e := range expect {
			if !slices.Contains(got, e) {
				allFound = false
				break
			}
		}
		if allFound {
			break
		}
		if attempt >= 19 {
			t.Fatalf("Expected contacts=%v to be received by pardot-test-srv, got contacts=%v", expect, got)
		}
	}
}

// TestContactsSentForNewAccount tests that contacts are dispatched to
// pardot-test-srv by the email-exporter when a new account is created.
func TestContactsSentForNewAccount(t *testing.T) {
	t.Parallel()

	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		t.Skip("Test requires WFE to be configured to use email-exporter")
	}

	domain := randomDomain(t)

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
			test.AssertNotError(t, err, "Failed to create initial account with contacts")
			assertAllContactsReceived(t, tt.expectContacts)
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

	domain := randomDomain(t)

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
			test.AssertNotError(t, err, "Failed to update contacts for existing account")
			assertAllContactsReceived(t, tt.expectContacts)
		})
	}
}
