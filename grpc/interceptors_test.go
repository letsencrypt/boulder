package grpc

import (
	"errors"
	"testing"
	"time"

	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/jmhodges/clock"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/letsencrypt/boulder/grpc/test_proto"
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
	si := serverInterceptor{grpc_prometheus.NewServerMetrics()}

	_, err := si.intercept(context.Background(), nil, nil, testHandler)
	test.AssertError(t, err, "si.intercept didn't fail with a nil grpc.UnaryServerInfo")

	_, err = si.intercept(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "-service-test"}, testHandler)
	test.AssertNotError(t, err, "si.intercept failed with a non-nil grpc.UnaryServerInfo")

	_, err = si.intercept(context.Background(), 0, &grpc.UnaryServerInfo{FullMethod: "brokeTest"}, testHandler)
	test.AssertError(t, err, "si.intercept didn't fail when handler returned a error")
}

func TestClientInterceptor(t *testing.T) {
	ci := clientInterceptor{time.Second, grpc_prometheus.NewClientMetrics()}
	err := ci.intercept(context.Background(), "-service-test", nil, nil, nil, testInvoker)
	test.AssertNotError(t, err, "ci.intercept failed with a non-nil grpc.UnaryServerInfo")

	err = ci.intercept(context.Background(), "-service-brokeTest", nil, nil, nil, testInvoker)
	test.AssertError(t, err, "ci.intercept didn't fail when handler returned a error")
}

// testServer is used to implement InterceptorTest
type testServer struct{}

// Chill implements InterceptorTest.Chill
func (s *testServer) Chill(ctx context.Context, in *test_proto.Time) (*test_proto.Time, error) {
	start := time.Now()
	time.Sleep(time.Duration(*in.Time) * time.Nanosecond)
	spent := int64(time.Since(start) / time.Nanosecond)
	return &test_proto.Time{Time: &spent}, nil
}

// TestFailFastFalse sends a gRPC request to a backend that is
// unavailable, and ensures that the request doesn't error out until the
// timeout is reached, i.e. that FailFast is set to false.
// https://github.com/grpc/grpc/blob/master/doc/wait-for-ready.md
func TestFailFastFalse(t *testing.T) {
	ci := &clientInterceptor{100 * time.Millisecond, grpc_prometheus.NewClientMetrics()}
	conn, err := grpc.Dial("localhost:19876", // random, probably unused port
		grpc.WithInsecure(),
		grpc.WithBalancer(grpc.RoundRobin(newStaticResolver([]string{"localhost:19000"}))),
		grpc.WithUnaryInterceptor(ci.intercept))
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	c := test_proto.NewChillerClient(conn)

	start := time.Now()
	var second int64 = time.Second.Nanoseconds()
	_, err = c.Chill(context.Background(), &test_proto.Time{Time: &second})
	if err == nil {
		t.Errorf("Successful Chill when we expected failure.")
	}
	if time.Since(start) < 90*time.Millisecond {
		t.Errorf("Chill failed fast, when FailFast should be disabled.")
	}
	_ = conn.Close()
}
