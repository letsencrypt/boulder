package grpc

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
)

const (
	returnOverhead         = 20 * time.Millisecond
	meaningfulWorkOverhead = 100 * time.Millisecond
	clientRequestTimeKey   = "client-request-time"
	serverLatencyKey       = "server-latency"
)

// serverInterceptor is a gRPC interceptor that adds Prometheus
// metrics to requests handled by a gRPC server, and wraps Boulder-specific
// errors for transmission in a grpc/metadata trailer (see bcodes.go).
type serverInterceptor struct {
	serverMetrics *grpc_prometheus.ServerMetrics
	rpcLag        prometheus.Histogram
	clk           clock.Clock
}

func newServerInterceptor(metrics serverMetrics, clk clock.Clock) serverInterceptor {
	return serverInterceptor{
		serverMetrics: metrics.GRPCMetrics,
		rpcLag:        metrics.RPCLag,
		clk:           clk,
	}
}

func (si *serverInterceptor) intercept(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if info == nil {
		return nil, berrors.InternalServerError("passed nil *grpc.UnaryServerInfo")
	}

	// Extract the grpc metadata from the context
	md, ok := metadata.FromContext(ctx)
	if !ok {
		return nil, berrors.InternalServerError("passed context with no grpc metadata")
	}
	// Ensure only one value is present
	if len(md[clientRequestTimeKey]) != 1 {
		return nil, berrors.InternalServerError("grpc metadata had illegal %s value: "+
			"expected 1 value, found %d",
			clientRequestTimeKey, len(md[clientRequestTimeKey]))
	}
	// Convert the metadata request time into an int64
	reqTimeStr := md[clientRequestTimeKey][0]
	reqTimeUnix, err := strconv.ParseInt(reqTimeStr, 10, 64)
	if err != nil {
		return nil, berrors.InternalServerError("grpc metadata had illegal %s value: %s - %s",
			clientRequestTimeKey, md[clientRequestTimeKey], err)
	}
	// Calculate the elapsed time since the client sent the RPC
	reqTime := time.Unix(0, reqTimeUnix)
	elapsed := si.clk.Now().Sub(reqTime)
	// Publish an RPC latency observation to the histogram
	si.rpcLag.Observe(elapsed.Seconds())

	if features.Enabled(features.RPCHeadroom) {
		// Shave 20 milliseconds off the deadline to ensure that if the RPC server times
		// out any sub-calls it makes (like DNS lookups, or onwards RPCs), it has a
		// chance to report that timeout to the client. This allows for more specific
		// errors, e.g "the VA timed out looking up CAA for example.com" (when called
		// from RA.NewCertificate, which was called from WFE.NewCertificate), as
		// opposed to "RA.NewCertificate timed out" (causing a 500).
		// Once we've shaved the deadline, we ensure we have we have at least another
		// 100ms left to do work; otherwise we abort early.
		deadline, ok := ctx.Deadline()
		// Should never happen: there was no deadline.
		if !ok {
			deadline = time.Now().Add(100 * time.Second)
		}
		deadline = deadline.Add(-returnOverhead)
		remaining := deadline.Sub(time.Now())
		if remaining < meaningfulWorkOverhead {
			return nil, grpc.Errorf(codes.DeadlineExceeded, "not enough time left on clock: %s", remaining)
		}
		var cancel func()
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}

	resp, err := si.serverMetrics.UnaryServerInterceptor()(ctx, req, info, handler)
	if err != nil {
		err = wrapError(ctx, err)
	}
	return resp, err
}

// splitMethodName is borrowed directly from
// `grpc-ecosystem/go-grpc-prometheus/util.go` and is used to extract the
// service and method name from the `method` argument to
// a `UnaryClientInterceptor`.
func splitMethodName(fullMethodName string) (string, string) {
	fullMethodName = strings.TrimPrefix(fullMethodName, "/") // remove leading slash
	if i := strings.Index(fullMethodName, "/"); i >= 0 {
		return fullMethodName[:i], fullMethodName[i+1:]
	}
	return "unknown", "unknown"
}

// clientInterceptor is a gRPC interceptor that adds Prometheus
// metrics to sent requests, and disables FailFast. We disable FailFast because
// non-FailFast mode is most similar to the old AMQP RPC layer: If a client
// makes a request while all backends are briefly down (e.g. for a restart), the
// request doesn't necessarily fail. A backend can service the request if it
// comes back up within the timeout. Under gRPC the same effect is achieved by
// retries up to the Context deadline.
type clientInterceptor struct {
	timeout       time.Duration
	clientMetrics *grpc_prometheus.ClientMetrics
	inFlightRPCs  *prometheus.GaugeVec
	clk           clock.Clock
}

// intercept fulfils the grpc.UnaryClientInterceptor interface, it should be noted that while this API
// is currently experimental the metrics it reports should be kept as stable as can be, *within reason*.
func (ci *clientInterceptor) intercept(
	ctx context.Context,
	fullMethod string,
	req,
	reply interface{},
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption) error {
	// This should not occur but fail fast with a clear error if it does (e.g.
	// because of buggy unit test code) instead of a generic nil panic later!
	if ci.inFlightRPCs == nil {
		return berrors.InternalServerError("clientInterceptor has nil inFlightRPCs gauge")
	}

	// Create a local context with the configured interceptor timeout
	localCtx, cancel := context.WithTimeout(ctx, ci.timeout)
	defer cancel()
	// Disable fail-fast so RPCs will retry until deadline, even if all backends
	// are down.
	opts = append(opts, grpc.FailFast(false))

	// Convert the current unix nano timestamp to a string for embedding in the grpc metadata
	nowTS := strconv.FormatInt(ci.clk.Now().UnixNano(), 10)
	// Create a grpc/metadata.Metadata instance. Initialize the metadata with the
	// request time.
	md := metadata.New(map[string]string{clientRequestTimeKey: nowTS})
	// Configure a grpc Trailer with the metadata. This allows us to wrap error
	// types in the server interceptor later on.
	opts = append(opts, grpc.Trailer(&md))
	// Configure the localCtx with the metadata so it gets sent along in the request
	localCtx = metadata.NewContext(localCtx, md)

	// Split the method and service name from the fullMethod.
	// UnaryClientInterceptor's receive a `method` arg of the form
	// "/ServiceName/MethodName"
	service, method := splitMethodName(fullMethod)
	// Slice the inFlightRPC inc/dec calls by method and service
	labels := prometheus.Labels{
		"method":  method,
		"service": service,
	}

	fmt.Printf("Incrementing inFlightRPCs for Labels: %#v\n", labels)
	// Increment the inFlightRPCs gauge for this method/service
	ci.inFlightRPCs.With(labels).Inc()
	// Handle the RPC
	err := ci.clientMetrics.UnaryClientInterceptor()(localCtx, fullMethod, req, reply, cc, invoker, opts...)
	if err != nil {
		err = unwrapError(err, md)
	}
	fmt.Printf("Decrementing inFlightRPCs for Labels: %#v\n", labels)
	// Decrement the inFlightRPCs gague
	ci.inFlightRPCs.With(labels).Dec()
	return err
}
