package ctpolicy

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	pubpb "github.com/letsencrypt/boulder/publisher/proto"
	"github.com/letsencrypt/boulder/test"
	"github.com/prometheus/client_golang/prometheus"
)

type mockPub struct {
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
	missingSCTErr := berrors.MissingSCTs
	testCases := []struct {
		name       string
		mock       core.Publisher
		groups     []cmd.CTGroup
		ctx        context.Context
		result     core.SCTDERs
		errRegexp  *regexp.Regexp
		berrorType *berrors.ErrorType
	}{
		{
			name: "basic success case",
			mock: &mockPub{},
			groups: []cmd.CTGroup{
				{
					Name: "a",
					Logs: []cmd.LogDescription{
						{URI: "abc", Key: "def"},
						{URI: "ghi", Key: "jkl"},
					},
				},
				{
					Name: "b",
					Logs: []cmd.LogDescription{
						{URI: "abc", Key: "def"},
						{URI: "ghi", Key: "jkl"},
					},
				},
			},
			ctx:    context.Background(),
			result: core.SCTDERs{[]byte{0}, []byte{0}},
		},
		{
			name: "basic failure case",
			mock: &alwaysFail{},
			groups: []cmd.CTGroup{
				{
					Name: "a",
					Logs: []cmd.LogDescription{
						{URI: "abc", Key: "def"},
						{URI: "ghi", Key: "jkl"},
					},
				},
				{
					Name: "b",
					Logs: []cmd.LogDescription{
						{URI: "abc", Key: "def"},
						{URI: "ghi", Key: "jkl"},
					},
				},
			},
			ctx:        context.Background(),
			errRegexp:  regexp.MustCompile("CT log group \".\": all submissions failed"),
			berrorType: &missingSCTErr,
		},
		{
			name: "parent context timeout failure case",
			mock: &alwaysFail{},
			groups: []cmd.CTGroup{
				{
					Name: "a",
					Logs: []cmd.LogDescription{
						{URI: "abc", Key: "def"},
						{URI: "ghi", Key: "jkl"},
					},
				},
				{
					Name: "b",
					Logs: []cmd.LogDescription{
						{URI: "abc", Key: "def"},
						{URI: "ghi", Key: "jkl"},
					},
				},
			},
			ctx:       expired,
			errRegexp: regexp.MustCompile("CT log group \".\": context deadline exceeded"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctp := New(tc.mock, tc.groups, nil, blog.NewMock(), metrics.NewNoopScope())
			ret, err := ctp.GetSCTs(tc.ctx, []byte{0}, time.Time{})
			if tc.result != nil {
				test.AssertDeepEquals(t, ret, tc.result)
			} else if tc.errRegexp != nil {
				if !tc.errRegexp.MatchString(err.Error()) {
					t.Errorf("Error %q did not match expected regexp %q", err, tc.errRegexp)
				}
				if tc.berrorType != nil {
					test.AssertEquals(t, berrors.Is(err, *tc.berrorType), true)
				}
			}
		})
	}
}

type failOne struct {
	mockPub

	badURL string
}

func (mp *failOne) SubmitToSingleCTWithResult(_ context.Context, req *pubpb.Request) (*pubpb.Result, error) {
	if *req.LogURL == mp.badURL {
		return nil, errors.New("BAD")
	}
	return &pubpb.Result{Sct: []byte{0}}, nil
}

func TestGetSCTsMetrics(t *testing.T) {
	ctp := New(&failOne{badURL: "abc"}, []cmd.CTGroup{
		{
			Name: "a",
			Logs: []cmd.LogDescription{
				{URI: "abc", Key: "def"},
				{URI: "ghi", Key: "jkl"},
			},
		},
		{
			Name: "b",
			Logs: []cmd.LogDescription{
				{URI: "abc", Key: "def"},
				{URI: "ghi", Key: "jkl"},
			},
		},
	}, nil, blog.NewMock(), metrics.NewNoopScope())
	_, err := ctp.GetSCTs(context.Background(), []byte{0}, time.Time{})
	test.AssertNotError(t, err, "GetSCTs failed")
	test.AssertEquals(t, test.CountCounter(ctp.winnerCounter.With(prometheus.Labels{"log": "ghi", "group": "a"})), 1)
	test.AssertEquals(t, test.CountCounter(ctp.winnerCounter.With(prometheus.Labels{"log": "ghi", "group": "b"})), 1)
}

// A mock publisher that counts submissions
type countEm struct {
	count int
}

func (ce *countEm) SubmitToSingleCTWithResult(_ context.Context, _ *pubpb.Request) (*pubpb.Result, error) {
	ce.count++
	return &pubpb.Result{Sct: []byte{0}}, nil
}

func TestStagger(t *testing.T) {
	countingPub := &countEm{}
	ctp := New(countingPub, []cmd.CTGroup{
		{
			Name:    "a",
			Stagger: cmd.ConfigDuration{Duration: 500 * time.Millisecond},
			Logs: []cmd.LogDescription{
				{URI: "abc", Key: "def"},
				{URI: "ghi", Key: "jkl"},
			},
		},
	}, nil, blog.NewMock(), metrics.NewNoopScope())
	_, err := ctp.GetSCTs(context.Background(), []byte{0}, time.Time{})
	test.AssertNotError(t, err, "GetSCTs failed")
	if countingPub.count != 1 {
		t.Errorf("wrong number of requests to publisher. got %d, expected 1", countingPub.count)
	}
}
