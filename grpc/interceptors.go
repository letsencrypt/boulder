package grpc

import (
	"errors"
	"fmt"

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
		si.stats.Inc("gRPC.NoInfo", 1)
		return nil, errors.New("passed nil *grpc.UnaryServerInfo")
	}
	s := si.clk.Now()
	si.stats.Inc(fmt.Sprintf("gRPC.%s", info.FullMethod), 1)
	si.stats.GaugeDelta(fmt.Sprintf("gRPC.%s.InProgress", info.FullMethod), 1)
	resp, err := handler(ctx, req)
	si.stats.TimingDuration(fmt.Sprintf("gRPC.%s", info.FullMethod), si.clk.Since(s))
	si.stats.GaugeDelta(fmt.Sprintf("gRPC.%s.InProgress", info.FullMethod), -1)
	if err != nil {
		si.stats.Inc(fmt.Sprintf("gRPC.%s.Failed", info.FullMethod), 1)
	}
	return resp, err
}

type clientInterceptor struct {
	stats metrics.Scope
	clk   clock.Clock
}

// intercept fulfils the grpc.UnaryClientInterceptor interface, it should be noted that while this API
// is currently experimental the metrics it reports should be kept as stable as can be, *within reason*
func (ci *clientInterceptor) intercept(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	s := ci.clk.Now()
	ci.stats.Inc(fmt.Sprintf("gRPC.%s", method), 1)
	flight := fmt.Sprintf("gRPC.%s.InProgress", method)
	ci.stats.GaugeDelta(flight, 1)
	err := invoker(ctx, method, req, reply, cc, opts...)
	ci.stats.TimingDuration(fmt.Sprintf("gRPC.%s", method), ci.clk.Since(s))
	ci.stats.GaugeDelta(flight, -1)
	if err != nil {
		ci.stats.Inc(fmt.Sprintf("gRPC.%s.Failed", method), 1)
	}
	return err
}
