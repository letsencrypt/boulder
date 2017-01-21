package grpc

import (
	"strings"
	"time"

	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/jmhodges/clock"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/letsencrypt/boulder/metrics"
	berrors "github.com/letsencrypt/boulder/errors"
)

// serverInterceptor is a gRPC interceptor that adds statsd and Prometheus
// metrics to requests handled by a gRPC server.
type serverInterceptor struct {
	stats metrics.Scope
	clk   clock.Clock
}

func cleanMethod(m string, trimService bool) string {
	m = strings.TrimLeft(m, "-")
	m = strings.Replace(m, "/", "_", -1)
	if trimService {
		s := strings.Split(m, "-")
		if len(s) == 1 {
			return m
		}
		return s[len(s)-1]
	}
	return strings.Replace(m, "-", "_", -1)
}

func (si *serverInterceptor) intercept(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if info == nil {
		si.stats.Inc("NoInfo", 1)
		return nil, berrors.New(berrors.InternalServer, "boulder/grpc: passed nil *grpc.UnaryServerInfo")
	}
	s := si.clk.Now()
	methodScope := si.stats.NewScope(cleanMethod(info.FullMethod, true))
	methodScope.Inc("Calls", 1)
	methodScope.GaugeDelta("InProgress", 1)
	resp, err := grpc_prometheus.UnaryServerInterceptor(ctx, req, info, handler)
	methodScope.TimingDuration("Latency", si.clk.Since(s))
	methodScope.GaugeDelta("InProgress", -1)
	if err != nil {
		methodScope.Inc("Failed", 1)
		err = wrapError(ctx, err)
	}
	return resp, err
}

// clientInterceptor is a gRPC interceptor that adds statsd and Prometheus
// metrics to sent requests, and disables FailFast. We disable FailFast because
// non-FailFast mode is most similar to the old AMQP RPC layer: If a client
// makes a request while all backends are briefly down (e.g. for a restart), the
// request doesn't necessarily fail. A backend can service the request if it
// comes back up within the timeout. Under gRPC the same effect is achieved by
// retries up to the Context deadline.
type clientInterceptor struct {
	stats   metrics.Scope
	clk     clock.Clock
	timeout time.Duration
}

// intercept fulfils the grpc.UnaryClientInterceptor interface, it should be noted that while this API
// is currently experimental the metrics it reports should be kept as stable as can be, *within reason*.
func (ci *clientInterceptor) intercept(
	ctx context.Context,
	method string,
	req,
	reply interface{},
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption) error {
	localCtx, cancel := context.WithTimeout(ctx, ci.timeout)
	defer cancel()
	s := ci.clk.Now()
	methodScope := ci.stats.NewScope(cleanMethod(method, false))
	methodScope.Inc("Calls", 1)
	methodScope.GaugeDelta("InProgress", 1)
	// Disable fail-fast so RPCs will retry until deadline, even if all backends
	// are down.
	opts = append(opts, grpc.FailFast(false))
	md := metadata.New(nil)
	opts = append(opts, grpc.Trailer(&md))
	err := grpc_prometheus.UnaryClientInterceptor(localCtx, method, req, reply, cc, invoker, opts...)
	methodScope.TimingDuration("Latency", ci.clk.Since(s))
	methodScope.GaugeDelta("InProgress", -1)
	if err != nil {
		methodScope.Inc("Failed", 1)
		err = unwrapError(err, md)
	}
	return err
}
