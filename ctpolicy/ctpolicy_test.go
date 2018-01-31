package ctpolicy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	pubpb "github.com/letsencrypt/boulder/publisher/proto"
	"github.com/letsencrypt/boulder/test"
)

type mockPub struct {
}

func (mp *mockPub) SubmitToCT(ctx context.Context, der []byte) error {
	return nil
}
func (mp *mockPub) SubmitToSingleCT(ctx context.Context, logURL, logPublicKey string, der []byte) error {
	return nil
}
func (mp *mockPub) SubmitToSingleCTWithResult(_ context.Context, _ *pubpb.Request) (*pubpb.Result, error) {
	return &pubpb.Result{Sct: []byte{0}}, nil
}

type alwaysFail struct {
	mockPub
}

func (mp *alwaysFail) SubmitToSingleCTWithResult(_ context.Context, _ *pubpb.Request) (*pubpb.Result, error) {
	return nil, errors.New("BAD")
}

func TestGetSCTs(t *testing.T) {
	expired, cancel := context.WithDeadline(context.Background(), time.Now())
	defer cancel()
	testCases := []struct {
		name   string
		mock   core.Publisher
		groups [][]cmd.LogDescription
		ctx    context.Context
		result []core.SCTDER
		err    error
	}{
		{
			name: "basic success case",
			mock: &mockPub{},
			groups: [][]cmd.LogDescription{
				{
					{URI: "abc", Key: "def"},
					{URI: "ghi", Key: "jkl"},
				},
				{
					{URI: "abc", Key: "def"},
					{URI: "ghi", Key: "jkl"},
				},
			},
			ctx:    context.Background(),
			result: []core.SCTDER{[]byte{0}, []byte{0}},
		},
		{
			name: "basic failure case",
			mock: &alwaysFail{},
			groups: [][]cmd.LogDescription{
				{
					{URI: "abc", Key: "def"},
					{URI: "ghi", Key: "jkl"},
				},
				{
					{URI: "abc", Key: "def"},
					{URI: "ghi", Key: "jkl"},
				},
			},
			ctx: context.Background(),
			err: errors.New("all submissions for group failed"),
		},
		{
			name: "parent context timeout failure case",
			mock: &alwaysFail{},
			groups: [][]cmd.LogDescription{
				{
					{URI: "abc", Key: "def"},
					{URI: "ghi", Key: "jkl"},
				},
				{
					{URI: "abc", Key: "def"},
					{URI: "ghi", Key: "jkl"},
				},
			},
			ctx: expired,
			err: context.DeadlineExceeded,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctp := New(tc.mock, tc.groups, blog.NewMock())
			ret, err := ctp.GetSCTs(tc.ctx, []byte{0})
			if tc.result != nil {
				test.AssertDeepEquals(t, ret, tc.result)
			} else if tc.err != nil {
				test.AssertDeepEquals(t, err, tc.err)
			}
		})
	}
}
