package grpc

import (
	"fmt"
	"net"
	"testing"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/letsencrypt/boulder/core"
	testproto "github.com/letsencrypt/boulder/grpc/test_proto"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"
)

type errorServer struct{}

func (s *errorServer) Chill(ctx context.Context, in *testproto.Time) (*testproto.Time, error) {
	var err error
	switch *in.Time {
	case 0:
		err = core.MalformedRequestError("yup")
	case 1:
		err = &probs.ProblemDetails{Type: probs.MalformedProblem, Detail: "yup"}
		// case 2:
		//	err = berrors.New(berrors.Malformed, "yup")
	}
	return nil, wrapError(err)
}

func TestErrorWrapping(t *testing.T) {
	srv := grpc.NewServer()
	testproto.RegisterChillerServer(srv, &errorServer{})
	lis, err := net.Listen("tcp", ":19876")
	test.AssertNotError(t, err, "Failed to listen on localhost:19876")
	go srv.Serve(lis)

	conn, err := grpc.Dial(
		"localhost:19876",
		grpc.WithInsecure(),
	)
	test.AssertNotError(t, err, "Failed to dial grpc test server")
	client := testproto.NewChillerClient(conn)

	for _, tc := range []struct {
		code     int64
		expected error
	}{
		{0, core.MalformedRequestError("yup")},
		{1, &probs.ProblemDetails{Type: probs.MalformedProblem, Detail: "yup"}},
	} {
		_, err := client.Chill(context.Background(), &testproto.Time{Time: &tc.code})
		test.Assert(t, err != nil, fmt.Sprintf("nil error returned, expected: %s", err))
		test.AssertDeepEquals(t, unwrapError(err), tc.expected)
	}
}
