//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

// getCreatedCases queries the pardot-test-srv for the list of created cases.
// Fails the test on error.
func getCreatedCases(t *testing.T, token string) []map[string]any {
	t.Helper()

	req, err := http.NewRequest("GET", "http://localhost:9601/cases", nil)
	test.AssertNotError(t, err, "Failed to create cases request")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	test.AssertNotError(t, err, "Failed to query cases")
	test.AssertEquals(t, resp.StatusCode, http.StatusOK)
	defer resp.Body.Close()

	var got struct {
		Cases []map[string]any `json:"cases"`
	}
	err = json.NewDecoder(resp.Body).Decode(&got)
	test.AssertNotError(t, err, "Failed to decode cases")
	return got.Cases
}

// createCase sends a request to create a new case via pardot-test-srv and
// returns the HTTP status code and response body. Fails the test on error.
func createCase(t *testing.T, token string, payload map[string]any) (int, []byte) {
	t.Helper()

	b, err := json.Marshal(payload)
	test.AssertNotError(t, err, "Failed to marshal case payload")

	req, err := http.NewRequest(
		"POST",
		"http://localhost:9601/services/data/v65.0/sobjects/Case",
		bytes.NewReader(b),
	)
	test.AssertNotError(t, err, "Failed to create case POST request")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	test.AssertNotError(t, err, "Failed to POST case")
	defer resp.Body.Close()

	var body bytes.Buffer
	_, err = body.ReadFrom(resp.Body)
	test.AssertNotError(t, err, "Failed to read case response body")

	return resp.StatusCode, body.Bytes()
}

func TestCasesAPISuccess(t *testing.T) {
	t.Parallel()

	token := getOAuthToken(t)

	status, _ := createCase(t, token, map[string]any{
		"Subject":     "Integration Test Case",
		"Description": "Created by integration test",
		"Origin":      "Web",
	})
	test.AssertEquals(t, status, http.StatusCreated)

	// Verify it was recorded by the fake server.
	cases := getCreatedCases(t, token)
	found := false
	for _, c := range cases {
		if c["Subject"] == "Integration Test Case" && c["Origin"] == "Web" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Expected created case to be present; got cases=%s", cases)
	}
}

func TestCasesAPIMissingOrigin(t *testing.T) {
	t.Parallel()

	token := getOAuthToken(t)

	// Missing Origin should be rejected by the fake server.
	status, body := createCase(t, token, map[string]any{
		"Subject":     "Missing Origin Case",
		"Description": "Should fail",
	})
	test.AssertEquals(t, status, http.StatusBadRequest)
	test.AssertContains(t, string(body), "Missing required field: Origin")
}
