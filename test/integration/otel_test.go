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

// TraceResponse is just the minimal fields we care about from the Jaeger traces API
type TraceData struct {
	TraceID string
	Spans   []struct {
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

// assertSpans checks the trace contains all the expected spans.
func assertSpans(t *testing.T, traceData TraceData, expectedSpans []string) {
	for _, expectedSpan := range expectedSpans {
		found := false
		for _, span := range traceData.Spans {
			if expectedSpan == span.OperationName {
				found = true
				break
			}
		}
		test.Assert(t, found, fmt.Sprintf("Didn't find expected span: %s in %v", expectedSpan, traceData))
	}
}

type ContextInjectingRoundTripper struct {
	ctx context.Context
}

func (c *ContextInjectingRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	otel.GetTextMapPropagator().Inject(c.ctx, propagation.HeaderCarrier(request.Header))
	return http.DefaultTransport.RoundTrip(request.WithContext(c.ctx))
}

// TestTraces tests that all the expected spans are present and properly connected
func TestTraces(t *testing.T) {
	t.Parallel()
	if !strings.Contains(os.Getenv("BOULDER_CONFIG_DIR"), "test/config-next") {
		t.Skip("OpenTelemetry is only configured in config-next")
	}

	traceID := traceIssuingTestCert(t)

	// Sleep to allow traces to flush
	// TODO: We could retry with backoff instead, allowing this test to complete faster.
	// TODO: We could also configure a lower batch delay in CI
	time.Sleep(1.2 * sdktrace.DefaultScheduleDelay * time.Millisecond)

	// TODO: We really want to assert more structure of the trace here
	traceData := getTraceFromJaeger(t, traceID)
	assertSpans(t, traceData, []string{
		"/directory",
		"/acme/new-acct",
		"sa.StorageAuthority/GetOrderForNames",
		"/acme/chall-v3/",
		"nonce.NonceService/Nonce",
	})

	test.AssertEquals(t, len(traceData.Warnings), 0)
	for _, span := range traceData.Spans {
		test.AssertEquals(t, len(span.Warnings), 0)
	}
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
