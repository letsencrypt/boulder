package grpc

import (
	"crypto/tls"
	"testing"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	"google.golang.org/grpc"
	_ "google.golang.org/grpc/health"
)

func TestClientSetup(t *testing.T) {
	type args struct {
		c            *cmd.GRPCClientConfig
		tlsConfig    *tls.Config
		metrics      clientMetrics
		clk          clock.Clock
		interceptors []grpc.UnaryClientInterceptor
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"valid, address provided", args{&cmd.GRPCClientConfig{ServerAddress: "localhost:8080"}, &tls.Config{}, clientMetrics{}, clock.NewFake(), []grpc.UnaryClientInterceptor{}}, false},
		{"valid, addresses provided", args{&cmd.GRPCClientConfig{ServerAddresses: []string{"127.0.0.1:8080"}}, &tls.Config{}, clientMetrics{}, clock.NewFake(), []grpc.UnaryClientInterceptor{}}, false},
		{"invalid, both address and addresses provided", args{&cmd.GRPCClientConfig{ServerAddress: "localhost:8080", ServerAddresses: []string{"127.0.0.1:8080"}}, &tls.Config{}, clientMetrics{}, clock.NewFake(), []grpc.UnaryClientInterceptor{}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ClientSetup(tt.args.c, tt.args.tlsConfig, tt.args.metrics, tt.args.clk, tt.args.interceptors...)
			if (err != nil) != tt.wantErr {
				t.Errorf("ClientSetup() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
