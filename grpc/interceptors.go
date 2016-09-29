package grpc

import (
	"errors"

	"github.com/letsencrypt/boulder/metrics"

	"github.com/jmhodges/clock"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

type serverInterceptor struct {
	stats metrics.Scope
	clk   clock.Clock
}

func (si *serverInterceptor) intercept(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if info == nil {
		si.stats.Inc("NoInfo", 1)
		return nil, errors.New("passed nil *grpc.UnaryServerInfo")
	}
	s := si.clk.Now()
	methodScope := si.stats.NewScope(info.FullMethod)
	methodScope.Inc("Calls", 1)
	methodScope.GaugeDelta("InProgress", 1)
	resp, err := handler(ctx, req)
	methodScope.TimingDuration("Latency", si.clk.Since(s))
	methodScope.GaugeDelta("InProgress", -1)
	if err != nil {
		methodScope.Inc("Failed", 1)
	}
	return resp, err
}

type clientInterceptor struct {
	stats metrics.Scope
	clk   clock.Clock
}

// intercept fulfils the grpc.UnaryClientInterceptor interface, it should be noted that while this API
// is currently experimental the metrics it reports should be kept as stable as can be, *within reason*.
func (ci *clientInterceptor) intercept(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	s := ci.clk.Now()
	methodScope := ci.stats.NewScope(method)
	methodScope.Inc("Calls", 1)
	methodScope.GaugeDelta("InProgress", 1)
	err := invoker(ctx, method, req, reply, cc, opts...)
	methodScope.TimingDuration("Latency", ci.clk.Since(s))
	methodScope.GaugeDelta("InProgress", -1)
	if err != nil {
		methodScope.Inc("Failed", 1)
	}
	return err
}
