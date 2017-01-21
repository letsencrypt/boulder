package grpc

import (
	"fmt"
	"net"
	"time"
	"testing"

	"golang.org/x/net/context"
	"github.com/jmhodges/clock"
	"google.golang.org/grpc"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/metrics"
	testproto "github.com/letsencrypt/boulder/grpc/test_proto"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"
	berrors "github.com/letsencrypt/boulder/errors"
)

type errorServer struct {
	err error
}

func (s *errorServer) Chill(_ context.Context, _ *testproto.Time) (*testproto.Time, error) {
	return nil, s.err
}

func TestErrorWrapping(t *testing.T) {
	fc := clock.NewFake()
	stats := metrics.NewNoopScope()
	si := serverInterceptor{stats, fc}
	ci := clientInterceptor{stats, fc, time.Second}
	srv := grpc.NewServer(grpc.UnaryInterceptor(si.intercept))
	es := &errorServer{}
	testproto.RegisterChillerServer(srv, es)
	lis, err := net.Listen("tcp", ":")
	test.AssertNotError(t, err, "Failed to create listener")
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	conn, err := grpc.Dial(
		lis.Addr().String(),
		grpc.WithInsecure(),
		grpc.WithUnaryInterceptor(ci.intercept),
	)
	test.AssertNotError(t, err, "Failed to dial grpc test server")
	client := testproto.NewChillerClient(conn)

	for _, tc := range []error{
		core.MalformedRequestError("yup"),
		&probs.ProblemDetails{Type: probs.MalformedProblem, Detail: "yup"},
		berrors.New(berrors.Malformed, "yup"),
	} {
		es.err = tc
		_, err := client.Chill(context.Background(), &testproto.Time{})
		test.Assert(t, err != nil, fmt.Sprintf("nil error returned, expected: %s", err))
		test.AssertDeepEquals(t, err, tc)
	}
}
