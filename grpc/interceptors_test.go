package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/jmhodges/clock"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
)

var fc = clock.NewFake()

func testHandler(_ context.Context, i interface{}) (interface{}, error) {
	if i != nil {
		return nil, errors.New("")
	}
	fc.Sleep(time.Second)
	return nil, nil
}

func testInvoker(_ context.Context, method string, _, _ interface{}, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
	if method == "-service-brokeTest" {
		return errors.New("")
	}
	fc.Sleep(time.Second)
	return nil
}

type mockInfo struct{}

func (m mockInfo) AuthType() string {
	return "MockInfo"
}

func TestServerWhitelistInterceptor(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	statter := metrics.NewMockStatter(ctrl)
	stats := metrics.NewStatsdScope(statter, "fake", "gRPCServer")

	whitelist := map[string]struct{}{
		"boulder": struct{}{},
	}

	si := serverWhitelistInterceptor{stats, whitelist, nil}

	// A nil grpc.UnaryServerInfo should produce an increment on
	// `fake.gRPCServer.NoInfo` and an error
	statter.EXPECT().Inc("fake.gRPCServer.NoInfo", int64(1), float32(1.0)).Return(nil)
	_, err := si.intercept(context.Background(), nil, nil, testHandler)
	test.AssertError(t, err,
		"serverWhitelistInterceptor.intercept didn't fail with a nil grpc.UnaryServerInfo")

	unaryServInfo := &grpc.UnaryServerInfo{FullMethod: "-service-test"}

	// A nil peer in the provided context should produce an increment on
	// `fake.gRPCServer.NoPeer` and an error
	statter.EXPECT().Inc("fake.gRPCServer.NoPeer", int64(1), float32(1.0)).Return(nil)
	_, err = si.intercept(context.Background(), nil, unaryServInfo, testHandler)
	test.AssertEquals(t, err.Error(), "passed context without *grpc.Peer")

	// A peer with a AuthInfo that isn't a credentials.TLSInfo should increment
	// the `fake.gRPCServer.NoPeerTLSInfo` stat and produce an error
	p := peer.Peer{
		AuthInfo: mockInfo{},
	}
	ctx := peer.NewContext(context.Background(), &p)
	statter.EXPECT().Inc("fake.gRPCServer.NoPeerTLSInfo", int64(1), float32(1.0)).Return(nil)
	_, err = si.intercept(ctx, nil, unaryServInfo, testHandler)
	test.AssertEquals(t, err.Error(), "peer did not have credentials.TLSInfo "+
		"as AuthInfo")

	// A peer with a TLSInfo that has a TLS state without any verified peer
	// certificates should increment the `fake.gRCPServer.NoPeerVerifiedChains`
	// stat and produce an error
	emptyTLSAuthInfo := credentials.TLSInfo{
		State: tls.ConnectionState{},
	}
	p.AuthInfo = emptyTLSAuthInfo
	statter.EXPECT().Inc("fake.gRPCServer.NoPeerVerifiedChains", int64(1), float32(1.0)).Return(nil)
	_, err = si.intercept(ctx, nil, unaryServInfo, testHandler)
	test.AssertEquals(t, err.Error(), "peer tlsInfo.State had zero VerifiedChains")

	// A peer presenting a chain that has a leaf certificate with a subject CN
	// that isn't on the whitelist should increment the
	// `fake.gRPCServer.PeerRejectedByWhitelist` stat and produce an error
	wrongCert, err := core.LoadCert("../test/test-root.pem")
	test.AssertNotError(t, err, "LoadCert failed for test/test-root.pem")
	wrongTLSAuthInfo := credentials.TLSInfo{
		State: tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{[]*x509.Certificate{wrongCert}},
		},
	}
	p.AuthInfo = wrongTLSAuthInfo
	statter.EXPECT().Inc("fake.gRPCServer.PeerRejectedByWhitelist", int64(1), float32(1.0)).Return(nil)
	_, err = si.intercept(ctx, nil, unaryServInfo, testHandler)
	test.AssertEquals(t, err.Error(),
		"peer's verified TLS chains did not include a leaf certificate with "+
			"whitelisted subject CN")

	// A peer presenting a chain with a leaf certificate that has a subject CN
	// matching an entry on the whitelist should produce no errors and increment
	// none of the error stats.
	validCert, err := core.LoadCert("../test/grpc-creds/client.pem")
	test.AssertNotError(t, err, "LoadCert failed for test/grpc-creds/client.pem")
	validTLSAuthInfo := credentials.TLSInfo{
		State: tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{[]*x509.Certificate{validCert}},
		},
	}
	p.AuthInfo = validTLSAuthInfo
	_, err = si.intercept(ctx, nil, unaryServInfo, testHandler)
	test.AssertNotError(t, err,
		"serverWhitelistInterceptor.intercept failed with a valid peer leaf subject CN")

	// A peer presenting one verified chain that matches, and one or more verified
	// chains that don't match should produce no errors and increment none of the
	// error stats.
	twoChainzAuthInfo := credentials.TLSInfo{
		State: tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{
				[]*x509.Certificate{wrongCert},
				[]*x509.Certificate{validCert},
			},
		},
	}
	p.AuthInfo = twoChainzAuthInfo
	_, err = si.intercept(ctx, nil, unaryServInfo, testHandler)
	test.AssertNotError(t, err,
		"serverWhitelistInterceptor.intercept failed with a valid peer leaf subject CN")
}

func TestServerStatsInterceptor(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	statter := metrics.NewMockStatter(ctrl)
	stats := metrics.NewStatsdScope(statter, "fake", "gRPCServer")
	si := serverStatsInterceptor{stats, fc}

	statter.EXPECT().Inc("fake.gRPCServer.NoInfo", int64(1), float32(1.0)).Return(nil)
	_, err := si.intercept(context.Background(), nil, nil, testHandler)
	test.AssertError(t, err, "si.intercept didn't fail with a nil grpc.UnaryServerInfo")

	statter.EXPECT().Inc("fake.gRPCServer.test.Calls", int64(1), float32(1.0)).Return(nil)
	statter.EXPECT().GaugeDelta("fake.gRPCServer.test.InProgress", int64(1), float32(1.0)).Return(nil)
	statter.EXPECT().TimingDuration("fake.gRPCServer.test.Latency", time.Second, float32(1.0)).Return(nil)
	statter.EXPECT().GaugeDelta("fake.gRPCServer.test.InProgress", int64(-1), float32(1.0)).Return(nil)
	_, err = si.intercept(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "-service-test"}, testHandler)
	test.AssertNotError(t, err, "si.intercept failed with a non-nil grpc.UnaryServerInfo")

	statter.EXPECT().Inc("fake.gRPCServer.brokeTest.Calls", int64(1), float32(1.0)).Return(nil)
	statter.EXPECT().GaugeDelta("fake.gRPCServer.brokeTest.InProgress", int64(1), float32(1.0)).Return(nil)
	statter.EXPECT().TimingDuration("fake.gRPCServer.brokeTest.Latency", time.Duration(0), float32(1.0)).Return(nil)
	statter.EXPECT().GaugeDelta("fake.gRPCServer.brokeTest.InProgress", int64(-1), float32(1.0)).Return(nil)
	statter.EXPECT().Inc("fake.gRPCServer.brokeTest.Failed", int64(1), float32(1.0)).Return(nil)
	_, err = si.intercept(context.Background(), 0, &grpc.UnaryServerInfo{FullMethod: "brokeTest"}, testHandler)
	test.AssertError(t, err, "si.intercept didn't fail when handler returned a error")
}

func TestClientStatsInterceptor(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	statter := metrics.NewMockStatter(ctrl)
	stats := metrics.NewStatsdScope(statter, "fake", "gRPCClient")
	ci := clientStatsInterceptor{stats, fc}

	statter.EXPECT().Inc("fake.gRPCClient.service_test.Calls", int64(1), float32(1.0)).Return(nil)
	statter.EXPECT().GaugeDelta("fake.gRPCClient.service_test.InProgress", int64(1), float32(1.0)).Return(nil)
	statter.EXPECT().TimingDuration("fake.gRPCClient.service_test.Latency", time.Second, float32(1.0)).Return(nil)
	statter.EXPECT().GaugeDelta("fake.gRPCClient.service_test.InProgress", int64(-1), float32(1.0)).Return(nil)
	err := ci.intercept(context.Background(), "-service-test", nil, nil, nil, testInvoker)
	test.AssertNotError(t, err, "ci.intercept failed with a non-nil grpc.UnaryServerInfo")

	statter.EXPECT().Inc("fake.gRPCClient.service_brokeTest.Calls", int64(1), float32(1.0)).Return(nil)
	statter.EXPECT().GaugeDelta("fake.gRPCClient.service_brokeTest.InProgress", int64(1), float32(1.0)).Return(nil)
	statter.EXPECT().TimingDuration("fake.gRPCClient.service_brokeTest.Latency", time.Duration(0), float32(1.0)).Return(nil)
	statter.EXPECT().GaugeDelta("fake.gRPCClient.service_brokeTest.InProgress", int64(-1), float32(1.0)).Return(nil)
	statter.EXPECT().Inc("fake.gRPCClient.service_brokeTest.Failed", int64(1), float32(1.0)).Return(nil)
	err = ci.intercept(context.Background(), "-service-brokeTest", nil, nil, nil, testInvoker)
	test.AssertError(t, err, "ci.intercept didn't fail when handler returned a error")
}

func TestCleanMethod(t *testing.T) {
	tests := []struct {
		in           string
		out          string
		stripService bool
	}{
		{"-ServiceName-MethodName", "ServiceName_MethodName", false},
		{"-ServiceName-MethodName", "MethodName", true},
		{"--MethodName", "MethodName", true},
		{"--MethodName", "MethodName", true},
		{"MethodName", "MethodName", false},
	}
	for _, tc := range tests {
		out := cleanMethod(tc.in, tc.stripService)
		if out != tc.out {
			t.Fatalf("cleanMethod didn't return the expected name: expected: %q, got: %q", tc.out, out)
		}
	}
}
