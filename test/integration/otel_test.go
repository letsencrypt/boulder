//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/test"
)

// TraceResponse is just the minimal fields we care about from the Jaeger traces API
type TraceResponse struct {
	Data []struct {
		Spans   []struct {
			OperationName string
		}
	}
}

func getWFEOperations(t *testing.T, op string) *TraceResponse {
	tracesURL := "http://jaeger:16686/api/traces?service=wfe2&operation=" + url.QueryEscape(op)
	fmt.Println(tracesURL)
	resp, err := http.Get(tracesURL)
	test.AssertNotError(t, err, "failed to fetch operation from jaeger")
	test.AssertEquals(t, resp.StatusCode, http.StatusOK)

	body, err := io.ReadAll(resp.Body)
	test.AssertNotError(t, err, "failed to read traces body")

	var parsed TraceResponse
	err = json.Unmarshal(body, &parsed)
	test.AssertNotError(t, err, "failed to decode traces body")

	test.Assert(t, len(parsed.Data) > 0, fmt.Sprintf("expected to get traces: %v (%s)", parsed, string(body)))

	return &parsed
}

// assertSpans checks that all the passed in traces contain the list of spans
func assertSpans(t *testing.T, tr *TraceResponse, spans []string) {
	for _, trace := range tr.Data {
		for _, span := range spans {
			found := false
			for _, a := range trace.Spans {
				if span == a.OperationName {
					found = true
					break;
				}
			}
			test.Assert(t, found, fmt.Sprintf("Didn't find expected span: %s in %v", span, trace))
		}
	}
}

// TestTraces tests that all the expected spans are present and properly connected
func TestTraces(t *testing.T) {
	t.Parallel()

	domains := []string{random_domain()}

	os.Setenv("DIRECTORY", "http://boulder.service.consul:4001/directory")
	_, err := authAndIssue(nil, nil, domains)
	test.AssertNotError(t, err, "authAndIssue failed")

	// Sleep a bit to allow traces to flush
	time.Sleep(5 * time.Second)

	// This map is a list of expected operations from WFE2.
	// The keys are a list of the other spans we expect to be present in
	// the traces. This isn't every span as that would be unwieldy, but is
	// enough to ensure tracing is functioning.
	ops := map[string][]string{
		"/directory": []string{},
	        "/acme/new-nonce": []string{
			"nonce.NonceService/Nonce",
		},
		"/acme/new-acct": []string{
			"nonce.NonceService/Nonce",
			"nonce.NonceService/Redeem",
			"ra.RegistrationAuthority/NewRegistration",
			"sa.StorageAuthority/KeyBlocked",
		},
		"/acme/new-order": []string{
			"nonce.NonceService/Nonce",
			"nonce.NonceService/Redeem",
			"sa.StorageAuthorityReadOnly/GetRegistration",
			"ra.RegistrationAuthority/NewOrder",
			"sa.StorageAuthority/NewOrderAndAuthzs",
		},
		"/acme/authz-v3/": []string{
			"nonce.NonceService/Nonce",
			"nonce.NonceService/Redeem",
			"sa.StorageAuthorityReadOnly/GetAuthorization2",
		},
		"/acme/chall-v3/": []string{
			"nonce.NonceService/Nonce",
			"nonce.NonceService/Redeem",
			"sa.StorageAuthorityReadOnly/GetAuthorization2",
		},
		"/acme/finalize/": []string{
			"nonce.NonceService/Nonce",
			"nonce.NonceService/Redeem",
			"sa.StorageAuthorityReadOnly/GetOrder",
			"ra.RegistrationAuthority/FinalizeOrder",
			"sa.StorageAuthority/KeyBlocked",
			"ca.CertificateAuthority/IssuePrecertificate",
			"Publisher/SubmitToSingleCTWithResult",
			"sa.StorageAuthority/FinalizeOrder",
		},
		"/acme/cert/": []string{
			"nonce.NonceService/Nonce",
			"nonce.NonceService/Redeem",
			"sa.StorageAuthorityReadOnly/GetCertificate",
		},
	}

	for op, spans := range ops {
		traces := getWFEOperations(t, op)
		assertSpans(t, traces, spans)
	}
}
