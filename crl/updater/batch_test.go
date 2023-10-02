package updater

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
)

func TestRunOnce(t *testing.T) {
	e1, err := issuance.LoadCertificate("../../test/hierarchy/int-e1.cert.pem")
	test.AssertNotError(t, err, "loading test issuer")
	r3, err := issuance.LoadCertificate("../../test/hierarchy/int-r3.cert.pem")
	test.AssertNotError(t, err, "loading test issuer")

	mockLog := blog.NewMock()
	clk := clock.NewFake()
	clk.Set(time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC))
	cu, err := NewUpdater(
		[]*issuance.Certificate{e1, r3},
		2, 18*time.Hour, 24*time.Hour,
		6*time.Hour, time.Minute, 1, 1,
		&fakeSAC{grcc: fakeGRCC{err: errors.New("db no worky")}, maxNotAfter: clk.Now().Add(90 * 24 * time.Hour)},
		&fakeCGC{gcc: fakeGCC{}},
		&fakeCSC{ucc: fakeUCC{}},
		metrics.NoopRegisterer, mockLog, clk,
	)
	test.AssertNotError(t, err, "building test crlUpdater")

	// An error that affects all issuers should have every issuer reflected in the
	// combined error message.
	err = cu.RunOnce(context.Background())
	test.AssertError(t, err, "database error")
	test.AssertContains(t, err.Error(), "one or more errors")
	test.AssertEquals(t, len(mockLog.GetAllMatching("Generating CRL failed:")), 4)
	cu.tickHistogram.Reset()
}

func TestGetShardMappings(t *testing.T) {
	// We set atTime to be exactly one day (numShards * shardWidth) after the
	// anchorTime for these tests, so that we know that the index of the first
	// chunk we would normally (i.e. not taking lookback or overshoot into
	// account) care about is 0.
	atTime := anchorTime().Add(24 * time.Hour)

	// When there is no lookback, and the maxNotAfter is exactly as far in the
	// future as the numShards * shardWidth looks, every shard should be mapped to
	// exactly one chunk.
	tcu := crlUpdater{
		numShards:      24,
		shardWidth:     1 * time.Hour,
		sa:             &fakeSAC{maxNotAfter: atTime.Add(23*time.Hour + 30*time.Minute)},
		lookbackPeriod: 0,
	}
	m, err := tcu.getShardMappings(context.Background(), atTime)
	test.AssertNotError(t, err, "getting aligned shards")
	test.AssertEquals(t, len(m), 24)
	for _, s := range m {
		test.AssertEquals(t, len(s), 1)
	}

	// When there is 1.5 hours each of lookback and maxNotAfter overshoot, then
	// there should be four shards which each get two chunks mapped to them.
	tcu = crlUpdater{
		numShards:      24,
		shardWidth:     1 * time.Hour,
		sa:             &fakeSAC{maxNotAfter: atTime.Add(24*time.Hour + 90*time.Minute)},
		lookbackPeriod: 90 * time.Minute,
	}
	m, err = tcu.getShardMappings(context.Background(), atTime)
	test.AssertNotError(t, err, "getting overshoot shards")
	test.AssertEquals(t, len(m), 24)
	for i, s := range m {
		if i == 0 || i == 1 || i == 22 || i == 23 {
			test.AssertEquals(t, len(s), 2)
		} else {
			test.AssertEquals(t, len(s), 1)
		}
	}

	// When there is a massive amount of overshoot, many chunks should be mapped
	// to each shard.
	tcu = crlUpdater{
		numShards:      24,
		shardWidth:     1 * time.Hour,
		sa:             &fakeSAC{maxNotAfter: atTime.Add(90 * 24 * time.Hour)},
		lookbackPeriod: time.Minute,
	}
	m, err = tcu.getShardMappings(context.Background(), atTime)
	test.AssertNotError(t, err, "getting overshoot shards")
	test.AssertEquals(t, len(m), 24)
	for i, s := range m {
		if i == 23 {
			test.AssertEquals(t, len(s), 91)
		} else {
			test.AssertEquals(t, len(s), 90)
		}
	}

	// An arbitrarily-chosen chunk should always end up in the same shard no
	// matter what the current time, lookback, and overshoot are, as long as the
	// number of shards and the shard width remains constant.
	tcu = crlUpdater{
		numShards:      24,
		shardWidth:     1 * time.Hour,
		sa:             &fakeSAC{maxNotAfter: atTime.Add(24 * time.Hour)},
		lookbackPeriod: time.Hour,
	}
	m, err = tcu.getShardMappings(context.Background(), atTime)
	test.AssertNotError(t, err, "getting consistency shards")
	test.AssertEquals(t, m[10][0].start, anchorTime().Add(34*time.Hour))
	tcu.lookbackPeriod = 4 * time.Hour
	m, err = tcu.getShardMappings(context.Background(), atTime)
	test.AssertNotError(t, err, "getting consistency shards")
	test.AssertEquals(t, m[10][0].start, anchorTime().Add(34*time.Hour))
	tcu.sa = &fakeSAC{maxNotAfter: atTime.Add(300 * 24 * time.Hour)}
	m, err = tcu.getShardMappings(context.Background(), atTime)
	test.AssertNotError(t, err, "getting consistency shards")
	test.AssertEquals(t, m[10][0].start, anchorTime().Add(34*time.Hour))
	atTime = atTime.Add(6 * time.Hour)
	m, err = tcu.getShardMappings(context.Background(), atTime)
	test.AssertNotError(t, err, "getting consistency shards")
	test.AssertEquals(t, m[10][0].start, anchorTime().Add(34*time.Hour))
}

func TestGetChunkAtTime(t *testing.T) {
	// Our test updater divides time into chunks 1 day wide, numbered 0 through 9.
	tcu := crlUpdater{
		numShards:  10,
		shardWidth: 24 * time.Hour,
	}

	// The chunk right at the anchor time should have index 0 and start at the
	// anchor time. This also tests behavior when atTime is on a chunk boundary.
	atTime := anchorTime()
	c, err := tcu.getChunkAtTime(atTime)
	test.AssertNotError(t, err, "getting chunk at anchor")
	test.AssertEquals(t, c.idx, 0)
	test.Assert(t, c.start.Equal(atTime), "getting chunk at anchor")
	test.Assert(t, c.end.Equal(atTime.Add(24*time.Hour)), "getting chunk at anchor")

	// The chunk a bit over a year in the future should have index 5.
	atTime = anchorTime().Add(365 * 24 * time.Hour)
	c, err = tcu.getChunkAtTime(atTime.Add(1 * time.Minute))
	test.AssertNotError(t, err, "getting chunk")
	test.AssertEquals(t, c.idx, 5)
	test.Assert(t, c.start.Equal(atTime), "getting chunk")
	test.Assert(t, c.end.Equal(atTime.Add(24*time.Hour)), "getting chunk")

	// A chunk very far in the future should break the math. We have to add to
	// the time twice, since the whole point of "very far in the future" is that
	// it isn't representable by a time.Duration.
	atTime = anchorTime().Add(200 * 365 * 24 * time.Hour).Add(200 * 365 * 24 * time.Hour)
	c, err = tcu.getChunkAtTime(atTime)
	test.AssertError(t, err, "getting far-future chunk")
}
