//go:build integration

package integration

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/eggsampler/acme/v3"
	"github.com/go-jose/go-jose/v4"

	"github.com/letsencrypt/boulder/test"
)

// TestTooBigOrderError tests that submitting an order with more than 100
// identifiers produces the expected problem result.
func TestTooBigOrderError(t *testing.T) {
	t.Parallel()

	var idents []acme.Identifier
	for i := range 101 {
		idents = append(idents, acme.Identifier{Type: "dns", Value: fmt.Sprintf("%d.example.com", i)})
	}

	_, err := authAndIssue(nil, nil, idents, true, "")
	test.AssertError(t, err, "authAndIssue failed")

	var prob acme.Problem
	test.AssertErrorWraps(t, err, &prob)
	test.AssertEquals(t, prob.Type, "urn:ietf:params:acme:error:malformed")
	test.AssertContains(t, prob.Detail, "Order cannot contain more than 100 identifiers")
}

func TestRejectedIdentifier(t *testing.T) {
	t.Parallel()

	// When a single malformed name is provided, we correctly reject it.
	idents := []acme.Identifier{
		{Type: "dns", Value: "яџ–Х6яяdь}"},
	}
	_, err := authAndIssue(nil, nil, idents, true, "")
	test.AssertError(t, err, "issuance should fail for one malformed name")
	var prob acme.Problem
	test.AssertErrorWraps(t, err, &prob)
	test.AssertEquals(t, prob.Type, "urn:ietf:params:acme:error:rejectedIdentifier")
	test.AssertContains(t, prob.Detail, "Domain name contains an invalid character")

	// When multiple malformed names are provided, we correctly reject all of
	// them and reflect this in suberrors. This test ensures that the way we
	// encode these errors across the gRPC boundary is resilient to non-ascii
	// characters.
	idents = []acme.Identifier{
		{Type: "dns", Value: "o-"},
		{Type: "dns", Value: "ш№Ў"},
		{Type: "dns", Value: "р±y"},
		{Type: "dns", Value: "яџ–Х6яя"},
		{Type: "dns", Value: "яџ–Х6яя`ь"},
	}
	_, err = authAndIssue(nil, nil, idents, true, "")
	test.AssertError(t, err, "issuance should fail for multiple malformed names")
	test.AssertErrorWraps(t, err, &prob)
	test.AssertEquals(t, prob.Type, "urn:ietf:params:acme:error:rejectedIdentifier")
	test.AssertContains(t, prob.Detail, "Domain name contains an invalid character")
	test.AssertContains(t, prob.Detail, "and 4 more problems")
}

// TestBadSignatureAlgorithm tests that supplying an unacceptable value for the
// "alg" field of the JWS Protected Header results in a problem document with
// the set of acceptable "alg" values listed in a custom extension field named
// "algorithms". Creating a request with an unacceptable "alg" field requires
// us to do some shenanigans.
func TestBadSignatureAlgorithm(t *testing.T) {
	t.Parallel()

	client, err := makeClient()
	if err != nil {
		t.Fatal("creating test client")
	}

	header, err := json.Marshal(&struct {
		Alg   string `json:"alg"`
		KID   string `json:"kid"`
		Nonce string `json:"nonce"`
		URL   string `json:"url"`
	}{
		Alg:   string(jose.RS512), // This is the important bit; RS512 is unacceptable.
		KID:   client.Account.URL,
		Nonce: "deadbeef", // This nonce would fail, but that check comes after the alg check.
		URL:   client.Directory().NewAccount,
	})
	if err != nil {
		t.Fatalf("creating JWS protected header: %s", err)
	}
	protected := base64.RawURLEncoding.EncodeToString(header)

	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"onlyReturnExisting": true}`))
	hash := crypto.SHA512.New()
	hash.Write([]byte(protected + "." + payload))
	sig, err := client.Account.PrivateKey.Sign(rand.Reader, hash.Sum(nil), crypto.SHA512)
	if err != nil {
		t.Fatalf("creating fake signature: %s", err)
	}

	data, err := json.Marshal(&struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}{
		Protected: protected,
		Payload:   payload,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	})

	req, err := http.NewRequest(http.MethodPost, client.Directory().NewAccount, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("creating HTTP request: %s", err)
	}
	req.Header.Set("Content-Type", "application/jose+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("making HTTP request: %s", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading HTTP response: %s", err)
	}

	var prob struct {
		Type       string                    `json:"type"`
		Detail     string                    `json:"detail"`
		Status     int                       `json:"status"`
		Algorithms []jose.SignatureAlgorithm `json:"algorithms"`
	}
	err = json.Unmarshal(body, &prob)
	if err != nil {
		t.Fatalf("parsing HTTP response: %s", err)
	}

	if prob.Type != "urn:ietf:params:acme:error:badSignatureAlgorithm" {
		t.Errorf("problem document has wrong type: want badSignatureAlgorithm, got %s", prob.Type)
	}
	if prob.Status != http.StatusBadRequest {
		t.Errorf("problem document has wrong status: want 400, got %d", prob.Status)
	}
	if len(prob.Algorithms) == 0 {
		t.Error("problem document MUST contain acceptable algorithms, got none")
	}
}
