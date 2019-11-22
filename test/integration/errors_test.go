// +build integration

package integration

import (
	"fmt"
	"os"
	"testing"

	"github.com/eggsampler/acme/v3"

	"github.com/letsencrypt/boulder/test"
)

// TestTooBigOrderError tests that submitting an order with more than 100 names
// produces the expected problem result.
func TestTooBigOrderError(t *testing.T) {
	t.Parallel()
	os.Setenv("DIRECTORY", "http://boulder:4001/directory")

	var domains []string
	for i := 0; i < 101; i++ {
		domains = append(domains, fmt.Sprintf("%d.example.com", i))
	}

	_, err := authAndIssue(nil, nil, domains)
	test.AssertError(t, err, "authAndIssue failed")

	if prob, ok := err.(acme.Problem); !ok {
		t.Fatalf("expected problem result, got %#v\n", err)
	} else {
		test.AssertEquals(t, prob.Type, "urn:ietf:params:acme:error:malformed")
		test.AssertEquals(t, prob.Detail, "Error creating new order :: Order cannot contain more than 100 DNS names")
	}
}
