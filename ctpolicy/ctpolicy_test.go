package ctpolicy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/ctpolicy/loglist"
	berrors "github.com/letsencrypt/boulder/errors"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	pubpb "github.com/letsencrypt/boulder/publisher/proto"
	"github.com/letsencrypt/boulder/test"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
)

type mockPub struct{}

func (mp *mockPub) SubmitToSingleCTWithResult(_ context.Context, _ *pubpb.Request, _ ...grpc.CallOption) (*pubpb.Result, error) {
	return &pubpb.Result{Sct: []byte{0}}, nil
}

type alwaysFail struct{}

func (mp *alwaysFail) SubmitToSingleCTWithResult(_ context.Context, _ *pubpb.Request, _ ...grpc.CallOption) (*pubpb.Result, error) {
	return nil, errors.New("BAD")
}

func TestGetSCTs(t *testing.T) {
	expired, cancel := context.WithDeadline(context.Background(), time.Now())
	defer cancel()
	missingSCTErr := berrors.MissingSCTs
	testCases := []struct {
		name       string
		mock       pubpb.PublisherClient
		groups     loglist.List
		ctx        context.Context
		result     core.SCTDERs
		expectErr  string
		berrorType *berrors.ErrorType
	}{
		{
			name: "basic success case",
			mock: &mockPub{},
			groups: loglist.List{
				"OperA": {
					"LogA1": {Url: "UrlA1", Key: "KeyA1"},
					"LogA2": {Url: "UrlA2", Key: "KeyA2"},
				},
				"OperB": {
					"LogB1": {Url: "UrlB1", Key: "KeyB1"},
				},
				"OperC": {
					"LogC1": {Url: "UrlC1", Key: "KeyC1"},
				},
			},
			ctx:    context.Background(),
			result: core.SCTDERs{[]byte{0}, []byte{0}},
		},
		{
			name: "basic failure case",
			mock: &alwaysFail{},
			groups: loglist.List{
				"OperA": {
					"LogA1": {Url: "UrlA1", Key: "KeyA1"},
					"LogA2": {Url: "UrlA2", Key: "KeyA2"},
				},
				"OperB": {
					"LogB1": {Url: "UrlB1", Key: "KeyB1"},
				},
				"OperC": {
					"LogC1": {Url: "UrlC1", Key: "KeyC1"},
				},
			},
			ctx:        context.Background(),
			expectErr:  "failed to get 2 SCTs, got error(s):",
			berrorType: &missingSCTErr,
		},
		{
			name: "parent context timeout failure case",
			mock: &alwaysFail{},
			groups: loglist.List{
				"OperA": {
					"LogA1": {Url: "UrlA1", Key: "KeyA1"},
					"LogA2": {Url: "UrlA2", Key: "KeyA2"},
				},
				"OperB": {
					"LogB1": {Url: "UrlB1", Key: "KeyB1"},
				},
				"OperC": {
					"LogC1": {Url: "UrlC1", Key: "KeyC1"},
				},
			},
			ctx:       expired,
			expectErr: "failed to get 2 SCTs before ctx finished",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctp := New(tc.mock, tc.groups, nil, nil, 0, blog.NewMock(), metrics.NoopRegisterer)
			ret, err := ctp.GetSCTs(tc.ctx, []byte{0}, time.Time{})
			if tc.result != nil {
				test.AssertDeepEquals(t, ret, tc.result)
			} else if tc.expectErr != "" {
				if !strings.Contains(err.Error(), tc.expectErr) {
					t.Errorf("Error %q did not match expected %q", err, tc.expectErr)
				}
				if tc.berrorType != nil {
					test.AssertErrorIs(t, err, *tc.berrorType)
				}
			}
		})
	}
}

type failOne struct {
	badURL string
}

func (mp *failOne) SubmitToSingleCTWithResult(_ context.Context, req *pubpb.Request, _ ...grpc.CallOption) (*pubpb.Result, error) {
	if req.LogURL == mp.badURL {
		return nil, errors.New("BAD")
	}
	return &pubpb.Result{Sct: []byte{0}}, nil
}

// TestGetSCTsMetrics checks that, when GetSCTs is successful, the "winner of
// SCT race" metric is incremented once for each of the two logs that we got an
// SCT from.
func TestGetSCTsMetrics(t *testing.T) {
	ctp := New(&mockPub{}, loglist.List{
		"a": {
			"Log1": {Url: "abc", Key: "def"},
		},
		"b": {
			"Log2": {Url: "ghi", Key: "jkl"},
		},
	}, nil, nil, 0, blog.NewMock(), metrics.NoopRegisterer)

	_, err := ctp.GetSCTs(context.Background(), []byte{0}, time.Time{})
	test.AssertNotError(t, err, "GetSCTs failed")
	test.AssertMetricWithLabelsEquals(t, ctp.winnerCounter, prometheus.Labels{"log": "abc", "group": "a"}, 1)
	test.AssertMetricWithLabelsEquals(t, ctp.winnerCounter, prometheus.Labels{"log": "ghi", "group": "b"}, 1)
}

// TestGetSCTsFailMetrics checks that, when all or all-but-one of the log groups
// fail, the call fails and the "winner of SCT race" metric is incremented
// to indicate that there were too many failures.
func TestGetSCTsFailMetrics(t *testing.T) {
	ctp := New(&failOne{badURL: "abc"}, loglist.List{
		"a": {
			"Log1": {Url: "abc", Key: "def"},
		},
		"b": {
			"Log1": {Url: "abc", Key: "def"},
		},
		"c": {
			"Log2": {Url: "ghi", Key: "jkl"},
		},
	}, nil, nil, 0, blog.NewMock(), metrics.NoopRegisterer)

	_, err := ctp.GetSCTs(context.Background(), []byte{0}, time.Time{})
	test.AssertError(t, err, "GetSCTs should have failed")
	test.AssertMetricWithLabelsEquals(t, ctp.winnerCounter, prometheus.Labels{"log": "all_failed", "group": "all_failed"}, 1)
}

type slowPublisher struct{}

func (sp *slowPublisher) SubmitToSingleCTWithResult(_ context.Context, req *pubpb.Request, _ ...grpc.CallOption) (*pubpb.Result, error) {
	time.Sleep(time.Second)
	return &pubpb.Result{Sct: []byte{0}}, nil
}

// TestGetSCTsFailMetrics checks that, when all or all-but-one of the log groups
// time out, the call fails and the "winner of SCT race" metric is incremented
// to indicate that there were too many timeouts.
func TestGetSCTsTimeoutMetrics(t *testing.T) {
	ctp := New(&slowPublisher{}, loglist.List{
		"a": {
			"Log1": {Url: "abc", Key: "def"},
		},
		"b": {
			"Log2": {Url: "ghi", Key: "jkl"},
		},
	}, nil, nil, 0, blog.NewMock(), metrics.NoopRegisterer)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := ctp.GetSCTs(ctx, []byte{0}, time.Time{})
	test.AssertError(t, err, "GetSCTs should have failed")
	test.AssertMetricWithLabelsEquals(t, ctp.winnerCounter, prometheus.Labels{"log": "timeout", "group": "timeout"}, 1)
}

// A mock publisher that counts submissions
type countEm struct {
	count int
}

func (ce *countEm) SubmitToSingleCTWithResult(_ context.Context, _ *pubpb.Request, _ ...grpc.CallOption) (*pubpb.Result, error) {
	ce.count++
	return &pubpb.Result{Sct: []byte{0}}, nil
}

// TestStagger checks that, when there are more than two groups, and the first
// two selected logs return SCTs quickly, requests are never sent to any other
// logs.
func TestStagger(t *testing.T) {
	countingPub := &countEm{}
	ctp := New(countingPub, loglist.List{
		"a": {
			"Log1": {Url: "abc", Key: "def"},
		},
		"b": {
			"Log1": {Url: "abc", Key: "def"},
		},
		"c": {
			"Log1": {Url: "abc", Key: "def"},
		},
	}, nil, nil, 500*time.Millisecond, blog.NewMock(), metrics.NoopRegisterer)

	_, err := ctp.GetSCTs(context.Background(), []byte{0}, time.Time{})
	test.AssertNotError(t, err, "GetSCTs failed")
	if countingPub.count != 2 {
		t.Errorf("wrong number of requests to publisher. got %d, expected 2", countingPub.count)
	}
}
