package ctpolicy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
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
func (mp *mockPub) SubmitToSingleCTWithResult(ctx context.Context, logURL, logPublicKey string, der []byte) ([]byte, error) {
	return []byte{0}, nil
}

type alwaysFail struct {
	mockPub
}

func (mp *alwaysFail) SubmitToSingleCTWithResult(ctx context.Context, logURL, logPublicKey string, der []byte) ([]byte, error) {
	return nil, errors.New("BAD")
}

func TestGetSCTs(t *testing.T) {
	expired, _ := context.WithDeadline(context.Background(), time.Now())
	testCases := []struct {
		name   string
		mock   core.Publisher
		groups [][]cmd.LogDescription
		ctx    context.Context
		result [][]byte
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
			result: [][]byte{[]byte{0}, []byte{0}},
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
			ctp := New(tc.mock, tc.groups)
			ret, err := ctp.GetSCTs(tc.ctx, []byte{0})
			if tc.result != nil {
				test.AssertDeepEquals(t, ret, tc.result)
			} else if tc.err != nil {
				test.AssertDeepEquals(t, err, tc.err)
			}
		})
	}
}
