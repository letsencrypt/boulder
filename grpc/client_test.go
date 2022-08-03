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
		name       string
		cfg        *cmd.GRPCClientConfig
		wantTarget string
		wantErr    bool
	}{
		{"valid, address provided", &cmd.GRPCClientConfig{ServerAddress: "localhost:8080"}, "dns:///localhost:8080", false},
		{"valid, implicit localhost with port provided", &cmd.GRPCClientConfig{ServerAddress: ":8080"}, "dns:///:8080", false},
		{"valid, two addresses provided", &cmd.GRPCClientConfig{ServerIPAddresses: []string{"127.0.0.1:8080", "127.0.0.2:8080"}}, "static:///127.0.0.1:8080,127.0.0.2:8080", false},
		{"valid, two addresses provided, one has an implicit localhost, ", &cmd.GRPCClientConfig{ServerIPAddresses: []string{":8080", "127.0.0.2:8080"}}, "static:///:8080,127.0.0.2:8080", false},
		{"invalid, both address and addresses provided", &cmd.GRPCClientConfig{ServerAddress: "localhost:8080", ServerIPAddresses: []string{"127.0.0.1:8080"}}, "", true},
		{"invalid, no address or addresses provided", &cmd.GRPCClientConfig{}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := ClientSetup(tt.cfg, &tls.Config{}, clientMetrics{}, clock.NewFake(), []grpc.UnaryClientInterceptor{}...)
			if (err != nil) != tt.wantErr {
				t.Errorf("ClientSetup() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantTarget != "" && client.Target() != tt.wantTarget {
				target := client.Target()
				t.Errorf("ClientSetup() target = %v, wantTarget %v", target, tt.wantTarget)
			}
		})
	}
}
