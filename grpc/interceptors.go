package grpc

import (
	"fmt"
	"time"

	"github.com/letsencrypt/boulder/metrics"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

type serverInterceptor struct {
	stats metrics.Statter
}

func (si *serverInterceptor) intercept(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	s := time.Now()
	si.stats.Inc(fmt.Sprintf("gRPC.%s", info.FullMethod), 1, 1.0)
	si.stats.GaugeDelta(fmt.Sprintf("gRPC.%s.InProgress", info.FullMethod), 1, 1.0)
	resp, err := handler(ctx, req)
	si.stats.GaugeDelta(fmt.Sprintf("gRPC.%s.InProgress", info.FullMethod), -1, 1.0)
	si.stats.TimingDuration(fmt.Sprintf("gRPC.%s", info.FullMethod), time.Since(s), 1.0)
	if err != nil {
		si.stats.Inc(fmt.Sprintf("gRPC.%s.Failed", info.FullMethod), 1, 1.0)
	}
	return resp, err
}
