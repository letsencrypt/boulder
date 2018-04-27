package grpc

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

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
	serverMetrics := NewServerMetrics(metrics.NewNoopScope())
	si := newServerInterceptor(serverMetrics, clock.NewFake())

	md := metadata.New(map[string]string{clientRequestTimeKey: "0"})
	ctxWithMetadata := metadata.NewContext(context.Background(), md)

	_, err := si.intercept(context.Background(), nil, nil, testHandler)
	test.AssertError(t, err, "si.intercept didn't fail with a context missing metadata")

	_, err = si.intercept(ctxWithMetadata, nil, nil, testHandler)
	test.AssertError(t, err, "si.intercept didn't fail with a nil grpc.UnaryServerInfo")

	_, err = si.intercept(ctxWithMetadata, nil, &grpc.UnaryServerInfo{FullMethod: "-service-test"}, testHandler)
	test.AssertNotError(t, err, "si.intercept failed with a non-nil grpc.UnaryServerInfo")

	_, err = si.intercept(ctxWithMetadata, 0, &grpc.UnaryServerInfo{FullMethod: "brokeTest"}, testHandler)
	test.AssertError(t, err, "si.intercept didn't fail when handler returned a error")
}

func TestClientInterceptor(t *testing.T) {
	ci := clientInterceptor{
		timeout: time.Second,
		metrics: NewClientMetrics(metrics.NewNoopScope()),
		clk:     clock.NewFake(),
	}
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
	ci := &clientInterceptor{
		timeout: 100 * time.Millisecond,
		metrics: NewClientMetrics(metrics.NewNoopScope()),
		clk:     clock.NewFake(),
	}
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

	serverMetrics := NewServerMetrics(metrics.NewNoopScope())
	si := newServerInterceptor(serverMetrics, clock.NewFake())
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
	ci := &clientInterceptor{
		timeout: 30 * time.Second,
		metrics: NewClientMetrics(metrics.NewNoopScope()),
		clk:     clock.NewFake(),
	}
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

func TestRequestTimeTagging(t *testing.T) {
	clk := clock.NewFake()
	// Listen for TCP requests on a random system assigned port number
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	// Retrieve the concrete port numberthe system assigned our listener
	port := lis.Addr().(*net.TCPAddr).Port

	// Create a new ChillerServer
	serverMetrics := NewServerMetrics(metrics.NewNoopScope())
	si := newServerInterceptor(serverMetrics, clk)
	s := grpc.NewServer(grpc.UnaryInterceptor(si.intercept))
	test_proto.RegisterChillerServer(s, &testServer{})
	// Chill until ill
	go func() {
		start := time.Now()
		if err := s.Serve(lis); err != nil &&
			!strings.HasSuffix(err.Error(), "use of closed network connection") {
			t.Fatalf("s.Serve: %v after %s", err, time.Since(start))
		}
	}()
	defer s.Stop()

	// Dial the ChillerServer
	ci := &clientInterceptor{
		timeout: 30 * time.Second,
		metrics: NewClientMetrics(metrics.NewNoopScope()),
		clk:     clk,
	}
	conn, err := grpc.Dial(net.JoinHostPort("localhost", fmt.Sprintf("%d", port)),
		grpc.WithInsecure(),
		grpc.WithUnaryInterceptor(ci.intercept))
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	// Create a ChillerClient with the connection to the ChillerServer
	c := test_proto.NewChillerClient(conn)

	// Make an RPC request with the ChillerClient with a timeout higher than the
	// requested ChillerServer delay so that the RPC completes normally
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var delayTime int64 = (time.Second * 5).Nanoseconds()
	_, err = c.Chill(ctx, &test_proto.Time{Time: &delayTime})
	if err != nil {
		t.Fatal(fmt.Sprintf("Unexpected error calling Chill RPC: %s", err))
	}

	// There should be one histogram sample in the serverInterceptor rpcLag stat
	count := test.CountHistogramSamples(si.metrics.rpcLag)
	test.AssertEquals(t, count, 1)
}

// blockedServer implements a ChillerServer with a Chill method that:
//   a) Calls Done() on the received waitgroup when receiving an RPC
//   b) Blocks the RPC on the roadblock waitgroup
// This is used by TestInFlightRPCStat to test that the gauge for in-flight RPCs
// is incremented and decremented as expected.
type blockedServer struct {
	roadblock, received sync.WaitGroup
}

// Chill implements ChillerServer.Chill
func (s *blockedServer) Chill(_ context.Context, _ *test_proto.Time) (*test_proto.Time, error) {
	// Note that a client RPC arrived
	s.received.Done()
	// Wait for the roadblock to be cleared
	s.roadblock.Wait()
	// Return a dummy spent value to adhere to the chiller protocol
	spent := int64(1)
	return &test_proto.Time{Time: &spent}, nil
}

func TestInFlightRPCStat(t *testing.T) {
	clk := clock.NewFake()
	// Listen for TCP requests on a random system assigned port number
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	// Retrieve the concrete port numberthe system assigned our listener
	port := lis.Addr().(*net.TCPAddr).Port

	// Create a new blockedServer to act as a ChillerServer
	server := &blockedServer{}

	// Increment the roadblock waitgroup - this will cause all chill RPCs to
	// the server to block until we call Done()!
	server.roadblock.Add(1)

	// Increment the sentRPCs waitgroup - we use this to find out when all the
	// RPCs we want to send have been received and we can count the in-flight
	// gauge
	numRPCs := 5
	server.received.Add(numRPCs)

	serverMetrics := NewServerMetrics(metrics.NewNoopScope())
	si := newServerInterceptor(serverMetrics, clk)
	s := grpc.NewServer(grpc.UnaryInterceptor(si.intercept))
	test_proto.RegisterChillerServer(s, server)
	// Chill until ill
	go func() {
		start := time.Now()
		if err := s.Serve(lis); err != nil &&
			!strings.HasSuffix(err.Error(), "use of closed network connection") {
			t.Fatalf("s.Serve: %v after %s", err, time.Since(start))
		}
	}()
	defer s.Stop()

	// Dial the ChillerServer
	ci := &clientInterceptor{
		timeout: 30 * time.Second,
		metrics: NewClientMetrics(metrics.NewNoopScope()),
		clk:     clk,
	}
	conn, err := grpc.Dial(net.JoinHostPort("localhost", fmt.Sprintf("%d", port)),
		grpc.WithInsecure(),
		grpc.WithUnaryInterceptor(ci.intercept))
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	// Create a ChillerClient with the connection to the ChillerServer
	c := test_proto.NewChillerClient(conn)

	// Fire off a few RPCs. They will block on the blockedServer's roadblock wg
	for i := 0; i < numRPCs; i++ {
		go func() {
			// Ignore errors, just chilllll.
			_, _ = c.Chill(context.Background(), &test_proto.Time{})
		}()
	}

	// wait until all of the client RPCs have been sent and are blocking. We can
	// now check the gauge.
	server.received.Wait()

	// Specify the labels for the RPCs we're interested in
	labels := prometheus.Labels{
		"service": "Chiller",
		"method":  "Chill",
	}

	// Retrieve the gauge for inflight Chiller.Chill RPCs
	inFlightCount, err := test.GaugeValueWithLabels(ci.metrics.inFlightRPCs, labels)
	test.AssertNotError(t, err, "Error collecting gauge value for inFlightRPCs")
	// We expect the inFlightRPCs gauge for the Chiller.Chill RPCs to be equal to numRPCs.
	test.AssertEquals(t, inFlightCount, numRPCs)

	// Unblock the blockedServer to let all of the Chiller.Chill RPCs complete
	server.roadblock.Done()
	// Sleep for a little bit to let all the RPCs complete
	time.Sleep(1 * time.Second)

	// Check the gauge value again
	inFlightCount, err = test.GaugeValueWithLabels(ci.metrics.inFlightRPCs, labels)
	test.AssertNotError(t, err, "Error collecting gauge value for inFlightRPCs")
	// There should now be zero in flight chill requests.
	// What a ~ ~ Chill Sitch ~ ~
	test.AssertEquals(t, inFlightCount, 0)
}
