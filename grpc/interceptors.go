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
	si.stats.Inc(fmt.Sprintf("gRPC.%s", info.FullMethod), 1)
	si.stats.GaugeDelta(fmt.Sprintf("gRPC.%s.InProgress", info.FullMethod), 1)
	s := si.clk.Now()
	resp, err := handler(ctx, req)
	si.stats.TimingDuration(fmt.Sprintf("gRPC.%s", info.FullMethod), si.clk.Now().Sub(s))
	si.stats.GaugeDelta(fmt.Sprintf("gRPC.%s.InProgress", info.FullMethod), -1)
	if err != nil {
		si.stats.Inc(fmt.Sprintf("gRPC.%s.Failed", info.FullMethod), 1)
	}
	return resp, err
}
