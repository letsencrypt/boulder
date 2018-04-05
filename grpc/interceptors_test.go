package grpc

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/jmhodges/clock"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/grpc/test_proto"
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

// testServer is used to implement TestTimeouts, and will attempt to sleep for
// the given amount of time (unless it hits a timeout or cancel).
type testServer struct{}

// Chill implements ChillerServer.Chill
func (s *testServer) Chill(ctx context.Context, in *test_proto.Time) (*test_proto.Time, error) {
	start := time.Now()
	// Sleep for either the requested amount of time, or the context times out or
	// is canceled.
	select {
	case <-time.After(time.Duration(*in.Time) * time.Nanosecond):
		spent := int64(time.Since(start) / time.Nanosecond)
		return &test_proto.Time{Time: &spent}, nil
	case <-ctx.Done():
		return nil, grpc.Errorf(codes.DeadlineExceeded, "the chiller overslept")
	}
}

func TestTimeouts(t *testing.T) {
	_ = features.Set(map[string]bool{"RPCHeadroom": true})
	defer features.Reset()
	// start server
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	port := lis.Addr().(*net.TCPAddr).Port

	si := &serverInterceptor{NewServerMetrics(metrics.NewNoopScope())}
	s := grpc.NewServer(grpc.UnaryInterceptor(si.intercept))
	test_proto.RegisterChillerServer(s, &testServer{})
	go func() {
		start := time.Now()
		if err := s.Serve(lis); err != nil &&
			!strings.HasSuffix(err.Error(), "use of closed network connection") {
			t.Fatalf("s.Serve: %v after %s", err, time.Since(start))
		}
	}()
	defer s.Stop()

	// make client
	ci := &clientInterceptor{30 * time.Second, grpc_prometheus.NewClientMetrics()}
	conn, err := grpc.Dial(net.JoinHostPort("localhost", fmt.Sprintf("%d", port)),
		grpc.WithInsecure(),
		grpc.WithUnaryInterceptor(ci.intercept))
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	c := test_proto.NewChillerClient(conn)

	testCases := []struct {
		timeout             time.Duration
		expectedErrorPrefix string
	}{
		{250 * time.Millisecond, "rpc error: code = Unknown desc = rpc error: code = DeadlineExceeded desc = the chiller overslept"},
		{100 * time.Millisecond, "rpc error: code = DeadlineExceeded desc = not enough time left on clock: "},
		{10 * time.Millisecond, "rpc error: code = DeadlineExceeded desc = not enough time left on clock: "},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s", tc.timeout), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
			defer cancel()
			var second int64 = time.Second.Nanoseconds()
			_, err := c.Chill(ctx, &test_proto.Time{Time: &second})
			if err == nil {
				t.Fatal("Got no error, expected a timeout")
			}
			if !strings.HasPrefix(err.Error(), tc.expectedErrorPrefix) {
				t.Errorf("Wrong error. Got %s, expected %s", err.Error(), tc.expectedErrorPrefix)
			}
		})
	}
}
