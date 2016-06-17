package grpc

import (
	"errors"
	"fmt"
	"time"

	"github.com/letsencrypt/boulder/metrics"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

type serverInterceptor struct {
	stats metrics.Scope
}

func (si *serverInterceptor) intercept(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if info == nil {
		return nil, errors.New("passed nil *grpc.UnaryServerInfo")
	}
	s := time.Now()
	si.stats.Inc(fmt.Sprintf("gRPC.%s", info.FullMethod), 1)
	si.stats.GaugeDelta(fmt.Sprintf("gRPC.%s.InProgress", info.FullMethod), 1)
	resp, err := handler(ctx, req)
	si.stats.GaugeDelta(fmt.Sprintf("gRPC.%s.InProgress", info.FullMethod), -1)
	si.stats.TimingDuration(fmt.Sprintf("gRPC.%s", info.FullMethod), time.Since(s))
	if err != nil {
		si.stats.Inc(fmt.Sprintf("gRPC.%s.Failed", info.FullMethod), 1)
	}
	return resp, err
}
