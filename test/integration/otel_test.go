//go:build integration

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/eggsampler/acme/v3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/test"
)

type SpanData struct {
	SpanID        string
	OperationName string
	Warnings      []string
	ProcessID     string
	References    []struct {
		RefType string
		TraceID string
		SpanID  string
	}
}

type TraceData struct {
	TraceID   string
	Spans     []SpanData
	Processes map[string]struct {
		ServiceName string
	}
	Warnings []string
}

// TraceResponse is what we get from the traces API.
// We always search for a single trace by ID, so this should be length 1.
type TraceResponse struct {
	Data []TraceData
}

func getTraceFromJaeger(t *testing.T, traceID trace.TraceID) TraceData {
	traceURL := "http://jaeger:16686/api/traces/" + traceID.String()
	resp, err := http.Get(traceURL)
	test.AssertNotError(t, err, "failed to trace from jaeger: "+traceID.String())
	if resp.StatusCode == http.StatusNotFound {
		t.Fatalf("jaeger returned 404 for trace %s", traceID)
	}
	test.AssertEquals(t, resp.StatusCode, http.StatusOK)

	body, err := io.ReadAll(resp.Body)
	test.AssertNotError(t, err, "failed to read trace body")

	var parsed TraceResponse
	err = json.Unmarshal(body, &parsed)
	test.AssertNotError(t, err, "failed to decode traces body")

	if len(parsed.Data) != 1 {
		t.Fatalf("expected to get exactly one trace for %s: %v", traceID, parsed)
	}

	return parsed.Data[0]
}

type expectedSpans struct {
	Operation string
	Service   string
	Children  []expectedSpans
}

// isParent returns true if the given span has a parent of ParentID
// The empty string means no ParentID
func isParent(parentID string, span SpanData) bool {
	if len(span.References) == 0 {
		return parentID == ""
	}
	for _, ref := range span.References {
		// In OpenTelemetry, CHILD_OF is the only reference, but Jaeger supports other systems.
		if ref.RefType == "CHILD_OF" {
			return ref.SpanID == parentID
		}
	}
	return false
}

func missingChildren(traceData TraceData, spanID string, children []expectedSpans) bool {
	for _, child := range children {
		if !findSpans(traceData, spanID, child) {
			// Missing Child
			return true
		}
	}
	return false
}

// findSpans checks if the expectedSpan and its expected children are found in traceData
func findSpans(traceData TraceData, parentSpan string, expectedSpan expectedSpans) bool {
	for _, span := range traceData.Spans {
		if !isParent(parentSpan, span) {
			continue
		}
		if expectedSpan.Service != traceData.Processes[span.ProcessID].ServiceName {
			continue
		}
		if expectedSpan.Operation != span.OperationName {
			continue
		}
		if missingChildren(traceData, span.SpanID, expectedSpan.Children) {
			continue
		}

		// This span has the correct parent, service, operation, and children
		return true
	}
	fmt.Printf("did not find span %s::%s with parent '%s'\n", expectedSpan.Service, expectedSpan.Operation, parentSpan)
	return false
}

type ContextInjectingRoundTripper struct {
	ctx context.Context
}

func (c *ContextInjectingRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	otel.GetTextMapPropagator().Inject(c.ctx, propagation.HeaderCarrier(request.Header))
	return http.DefaultTransport.RoundTrip(request.WithContext(c.ctx))
}

// rpcSpan is a helper for constructing an RPC span where we have both a client and server rpc operation
func rpcSpan(op, client, server string, children ...expectedSpans) expectedSpans {
	return expectedSpans{
		Operation: op,
		Service:   client,
		Children: []expectedSpans{
			{
				Operation: op,
				Service:   server,
				Children:  children,
			},
		},
	}
}

func httpSpan(endpoint string, children ...expectedSpans) expectedSpans {
	return expectedSpans{
		Operation: endpoint,
		Service:   "boulder-wfe2",
		Children: append(children,
			rpcSpan("nonce.NonceService/Nonce", "boulder-wfe2", "nonce-service"),
			rpcSpan("nonce.NonceService/Redeem", "boulder-wfe2", "nonce-service"),
		),
	}
}

// TestTraces tests that all the expected spans are present and properly connected
func TestTraces(t *testing.T) {
	t.Parallel()
	if !strings.Contains(os.Getenv("BOULDER_CONFIG_DIR"), "test/config-next") {
		t.Skip("OpenTelemetry is only configured in config-next")
	}

	traceID := traceIssuingTestCert(t)

	wfe := "boulder-wfe2"
	sa := "boulder-sa"
	ra := "boulder-ra"
	ca := "boulder-ca"

	expectedSpans := expectedSpans{
		Operation: "TraceTest",
		Service:   "integration.test",
		Children: []expectedSpans{
			{Operation: "/directory", Service: wfe},
			{Operation: "/acme/new-nonce", Service: wfe, Children: []expectedSpans{
				rpcSpan("nonce.NonceService/Nonce", wfe, "nonce-service")}},
			httpSpan("/acme/new-acct",
				rpcSpan("sa.StorageAuthorityReadOnly/KeyBlocked", wfe, sa),
				rpcSpan("sa.StorageAuthorityReadOnly/GetRegistrationByKey", wfe, sa),
				rpcSpan("ra.RegistrationAuthority/NewRegistration", wfe, ra,
					rpcSpan("sa.StorageAuthority/KeyBlocked", ra, sa),
					rpcSpan("sa.StorageAuthority/CountRegistrationsByIP", ra, sa),
					rpcSpan("sa.StorageAuthority/NewRegistration", ra, sa))),
			httpSpan("/acme/new-order",
				rpcSpan("sa.StorageAuthorityReadOnly/GetRegistration", wfe, sa),
				rpcSpan("ra.RegistrationAuthority/NewOrder", wfe, ra,
					rpcSpan("sa.StorageAuthority/GetOrderForNames", ra, sa),
					// 8 ra -> sa rate limit spans omitted here
					rpcSpan("sa.StorageAuthority/NewOrderAndAuthzs", ra, sa))),
			httpSpan("/acme/authz-v3/",
				rpcSpan("sa.StorageAuthorityReadOnly/GetAuthorization2", wfe, sa)),
			httpSpan("/acme/chall-v3/",
				rpcSpan("sa.StorageAuthorityReadOnly/GetAuthorization2", wfe, sa),
				rpcSpan("ra.RegistrationAuthority/PerformValidation", wfe, ra,
					rpcSpan("sa.StorageAuthority/GetRegistration", ra, sa))),
			httpSpan("/acme/finalize/",
				rpcSpan("sa.StorageAuthorityReadOnly/GetOrder", wfe, sa),
				rpcSpan("ra.RegistrationAuthority/FinalizeOrder", wfe, ra,
					rpcSpan("sa.StorageAuthority/KeyBlocked", ra, sa),
					rpcSpan("sa.StorageAuthority/GetRegistration", ra, sa),
					rpcSpan("sa.StorageAuthority/GetValidOrderAuthorizations2", ra, sa),
					rpcSpan("sa.StorageAuthority/SetOrderProcessing", ra, sa),
					rpcSpan("ca.CertificateAuthority/IssuePrecertificate", ra, ca),
					rpcSpan("Publisher/SubmitToSingleCTWithResult", ra, "boulder-publisher"),
					rpcSpan("ca.CertificateAuthority/IssueCertificateForPrecertificate", ra, ca),
					rpcSpan("sa.StorageAuthority/FinalizeOrder", ra, sa))),
			httpSpan("/acme/order/", rpcSpan("sa.StorageAuthorityReadOnly/GetOrder", wfe, sa)),
			httpSpan("/acme/cert/", rpcSpan("sa.StorageAuthorityReadOnly/GetCertificate", wfe, sa)),
		},
	}

	// Retry checking for spans. Span submission is batched asynchronously, so we
	// may have to wait for the DefaultScheduleDelay (5 seconds) for results to
	// be available. Rather than always waiting, we retry a few times.
	// Empirically, this test passes on the second or third try.
	const retries = 10
	for try := 0; try < retries; try++ {
		traceData := getTraceFromJaeger(t, traceID)
		if findSpans(traceData, "", expectedSpans) {
			test.AssertEquals(t, len(traceData.Warnings), 0)
			for _, span := range traceData.Spans {
				if len(span.Warnings) != 0 && try != retries-1 {
					// We got a warning, which is likely a missing parent span, so continue unless it's our final try
					t.Fatalf("Span %s (%s) warning: %v", span.SpanID, span.OperationName, span.Warnings)
				}
			}
			return
		}
		time.Sleep(sdktrace.DefaultScheduleDelay / 5 * time.Millisecond)
	}
	t.Fatalf("Failed to find expected spans in Jaeger for trace %s\n", traceID)
}

func traceIssuingTestCert(t *testing.T) trace.TraceID {
	domains := []string{random_domain()}

	// Configure this integration test to trace to jaeger:4317 like Boulder will
	shutdown := cmd.NewOpenTelemetry(cmd.OpenTelemetryConfig{
		Endpoint:    "jaeger:4317",
		SampleRatio: 1,
	}, blog.Get())
	defer shutdown(context.Background())

	tracer := otel.GetTracerProvider().Tracer("TraceTest")
	ctx, span := tracer.Start(context.Background(), "TraceTest")
	defer span.End()

	// Provide an HTTP client with otel spans.
	// The acme client doesn't pass contexts through, so we inject one.
	option := acme.WithHTTPClient(&http.Client{
		Timeout:   60 * time.Second,
		Transport: &ContextInjectingRoundTripper{ctx},
	})

	c, err := acme.NewClient("http://boulder.service.consul:4001/directory", option)
	test.AssertNotError(t, err, "newAccount failed")

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "newAccount failed")

	account, err := c.NewAccount(privKey, false, true)
	test.AssertNotError(t, err, "newAccount failed")

	_, err = authAndIssue(&client{account, c}, nil, domains, true)
	test.AssertNotError(t, err, "authAndIssue failed")

	return span.SpanContext().TraceID()
}
