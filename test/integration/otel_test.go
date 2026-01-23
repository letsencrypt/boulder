//go:build integration

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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

// Trace is the list of traces returned from ClickHouse for this trace
type Trace struct {
	Data []Span
}

// Span in clickhouse results
type Span struct {
	TraceId      string
	SpanId       string
	ParentSpanId string
	SpanName     string
	ServiceName  string
}

func getTraceFromClickHouse(t *testing.T, traceID trace.TraceID) Trace {
	t.Helper()

	query := fmt.Sprintf("SELECT TraceId, SpanId, ParentSpanId, SpanName, ServiceName FROM otel.otel_traces WHERE TraceId = '%s'", traceID.String())
	clickhouseURL := fmt.Sprintf("https://clickhouse:8443/?default_format=JSON&query=%s", url.QueryEscape(query))

	req, err := http.NewRequest("GET", clickhouseURL, nil)
	test.AssertNotError(t, err, "failed to create request")
	req.SetBasicAuth("default", "default_user_very_bad_password")

	caCert, err := os.ReadFile("../certs/ipki/minica.pem")
	test.AssertNotError(t, err, "failed to read CA cert")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	clientCert, err := tls.LoadX509KeyPair("../certs/ipki/otel-collector/cert.pem", "../certs/ipki/otel-collector/key.pem")
	test.AssertNotError(t, err, "failed to load client key pair")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:            caCertPool,
			Certificates:       []tls.Certificate{clientCert},
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	test.AssertNotError(t, err, "failed to query clickhouse")
	defer resp.Body.Close()
	test.AssertEquals(t, resp.StatusCode, http.StatusOK)

	var response Trace
	test.AssertNotError(t, json.NewDecoder(resp.Body).Decode(&response), "failed to decode clickhouse response")

	return response
}

type expectedSpans struct {
	SpanName string
	Service  string
	Children []expectedSpans
}

func missingChildren(trace Trace, spanID string, children []expectedSpans) bool {
	for _, child := range children {
		if !findSpans(trace, spanID, child) {
			// Missing Child
			return true
		}
	}
	return false
}

// findSpans checks if the expectedSpan and its expected children are found in trace
func findSpans(trace Trace, parentSpan string, expectedSpan expectedSpans) bool {
	for _, span := range trace.Data {
		if span.ParentSpanId != parentSpan {
			continue
		}
		if span.ServiceName != expectedSpan.Service {
			continue
		}
		if span.SpanName != expectedSpan.SpanName {
			continue
		}
		if missingChildren(trace, span.SpanId, expectedSpan.Children) {
			continue
		}

		// This span has the correct parent, service, operation, and children
		return true
	}
	fmt.Printf("did not find span %s::%s with parent '%s'\n", expectedSpan.Service, expectedSpan.SpanName, parentSpan)
	return false
}

// ContextInjectingRoundTripper holds a context that is added to every request
// sent through this RoundTripper, propagating the OpenTelemetry trace through
// the requests made with it.
//
// This is useful for tracing HTTP clients which don't pass through a context,
// notably including the eggsampler ACME client used in this test.
//
// This test uses a trace started in the test to connect all the outgoing
// requests into a trace that is retrieved from Jaeger's API to make assertions
// about the spans from Boulder.
type ContextInjectingRoundTripper struct {
	ctx context.Context
}

// RoundTrip implements http.RoundTripper, injecting c.ctx and the OpenTelemetry
// propagation headers into the request. This ensures all requests are traced.
func (c *ContextInjectingRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	// RoundTrip is not permitted to modify the request, so we clone with this context
	r := request.Clone(c.ctx)
	// Inject the otel propagation headers
	otel.GetTextMapPropagator().Inject(c.ctx, propagation.HeaderCarrier(r.Header))
	return http.DefaultTransport.RoundTrip(r)
}

// rpcSpan is a helper for constructing an RPC span where we have both a client and server rpc operation
func rpcSpan(op, client, server string, children ...expectedSpans) expectedSpans {
	return expectedSpans{
		SpanName: op,
		Service:  client,
		Children: []expectedSpans{
			{
				SpanName: op,
				Service:  server,
				Children: children,
			},
		},
	}
}

func httpSpan(endpoint string, children ...expectedSpans) expectedSpans {
	return expectedSpans{
		SpanName: endpoint,
		Service:  "boulder-wfe2",
		Children: append(children,
			rpcSpan("nonce.NonceService/Nonce", "boulder-wfe2", "nonce-service"),
			rpcSpan("nonce.NonceService/Redeem", "boulder-wfe2", "nonce-service"),
		),
	}
}

func redisPipelineSpan(op, service string, children ...expectedSpans) expectedSpans {
	return expectedSpans{
		SpanName: "redis.pipeline " + op,
		Service:  service,
		Children: children,
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
	ra := "boulder-ra"
	ca := "boulder-ca"

	// A very stripped-down version of the expected call graph of a full issuance
	// flow: just enough to ensure that our otel tracing is working without
	// asserting too much about the exact set of RPCs we use under the hood.
	expectedSpans := expectedSpans{
		SpanName: "TraceTest",
		Service:  "integration.test",
		Children: []expectedSpans{
			{SpanName: "/directory", Service: wfe},
			{SpanName: "/acme/new-nonce", Service: wfe, Children: []expectedSpans{
				rpcSpan("nonce.NonceService/Nonce", wfe, "nonce-service")}},
			httpSpan("/acme/new-acct",
				redisPipelineSpan("get", wfe)),
			httpSpan("/acme/new-order"),
			httpSpan("/acme/authz/"),
			httpSpan("/acme/chall/"),
			httpSpan("/acme/finalize/",
				rpcSpan("ra.RegistrationAuthority/FinalizeOrder", wfe, ra,
					rpcSpan("ca.CertificateAuthority/IssueCertificate", ra, ca))),
		},
	}

	// Retry checking for spans. Span submission is batched asynchronously, so we
	// may have to wait for the DefaultScheduleDelay (5 seconds) for results to
	// be available. Rather than always waiting, we retry a few times.
	// Empirically, this test passes on the second or third try.
	var trace Trace
	found := false
	const retries = 10
	for range retries {
		trace = getTraceFromClickHouse(t, traceID)
		if findSpans(trace, "", expectedSpans) {
			found = true
			break
		}
		time.Sleep(sdktrace.DefaultScheduleDelay / 5 * time.Millisecond)
	}
	test.Assert(t, found, fmt.Sprintf("Failed to find expected spans in ClickHouse for trace %s", traceID))
}

func traceIssuingTestCert(t *testing.T) trace.TraceID {
	// Configure this integration test to trace to otel-collector:4317 like Boulder will
	shutdown := cmd.NewOpenTelemetry(cmd.OpenTelemetryConfig{
		Endpoint:    "otel-collector:4317",
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
	test.AssertNotError(t, err, "acme.NewClient failed")

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "Generating ECDSA key failed")

	account, err := c.NewAccount(privKey, false, true)
	test.AssertNotError(t, err, "newAccount failed")

	_, err = authAndIssue(&client{account, c}, nil, []acme.Identifier{{Type: "dns", Value: random_domain()}}, true, "")
	test.AssertNotError(t, err, "authAndIssue failed")

	return span.SpanContext().TraceID()
}
