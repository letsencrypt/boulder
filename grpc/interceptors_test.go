package grpc

//go:generate sh -c "cd .. && protoc --go_out=plugins=grpc,Mcore/proto/core.proto=github.com/letsencrypt/boulder/grpc:. grpc/interceptors_test.proto"

import (
	"errors"
	"log"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/jmhodges/clock"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

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

func testInvoker(_ context.Context, method string, _, _ interface{}, _ *grpc.ClientConn, opts ...grpc.CallOption) error {
	if method == "-service-brokeTest" {
		return errors.New("")
	}
	fc.Sleep(time.Second)
	return nil
}

func TestServerInterceptor(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	statter := metrics.NewMockStatter(ctrl)
	stats := metrics.NewStatsdScope(statter, "fake", "gRPCServer")
	si := serverInterceptor{stats, fc}

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

func TestClientInterceptor(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	statter := metrics.NewMockStatter(ctrl)
	stats := metrics.NewStatsdScope(statter, "fake", "gRPCClient")
	ci := clientInterceptor{stats, fc, time.Second}

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

// testServer is used to implement InterceptorTest
type testServer struct{}

// Chill implements InterceptorTest.Chill
func (s *testServer) Chill(ctx context.Context, in *Time) (*Time, error) {
	start := time.Now()
	time.Sleep(time.Duration(*in.Time) * time.Nanosecond)
	spent := int64(time.Since(start) / time.Nanosecond)
	return &Time{Time: &spent}, nil
}

func TestInterceptors(t *testing.T) {
	// Set up a connection to a nonexistent server.
	ci := &clientInterceptor{metrics.NewNoopScope(), clock.Default(), 1100 * time.Millisecond}
	conn, err := grpc.Dial(net.JoinHostPort("localhost", strconv.Itoa(port)),
		grpc.WithInsecure(),
		grpc.WithBalancer(grpc.RoundRobin(newStaticResolver([]string{"localhost:19000"}))),
		grpc.WithUnaryInterceptor(ci.intercept))
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := NewInterceptorTestClient(conn)

	/*
		lis, err := net.Listen("tcp", ":0")
		if err != nil {
			log.Fatalf("failed to listen: %v", err)
		}
		port := lis.Addr().(*net.TCPAddr).Port

		si := &serverInterceptor{metrics.NewNoopScope(), clock.Default()}
		s := grpc.NewServer(grpc.UnaryInterceptor(si.intercept))
		RegisterInterceptorTestServer(s, &testServer{})
		go func() {
			start := time.Now()
			if err := s.Serve(lis); err != nil &&
				!strings.HasSuffix(err.Error(), "use of closed network connection") {
				t.Fatalf("s.Serve: %v after %s", err, time.Since(start))
			}
		}()

	*/
	start := time.Now()
	var second int64 = time.Second.Nanoseconds()
	_, err = c.Chill(context.Background(), &Time{Time: &second})
	if err == nil {
		t.Fatal("Successful Chill when we expected failure.")
	}
	if time.Since(start) < 100*time.Millisecond {
		t.Fatal("Chill failed fast, when FailFast should be disabled.")
	}

	//s.GracefulStop()
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
