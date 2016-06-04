package metrics

import (
	"testing"
	"time"

	"github.com/golang/mock/gomock"
)

func TestScopedStatsStatsd(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	statter := NewMockStatter(ctrl)
	stats := NewStatsdScope(statter, "fake")
	statter.EXPECT().Inc("fake.counter", int64(2), float32(1.0)).Return(nil)
	stats.Inc("counter", 2)

	statter.EXPECT().Dec("fake.counter", int64(2), float32(1.0)).Return(nil)
	stats.Dec("counter", 2)

	statter.EXPECT().Gauge("fake.gauge", int64(2), float32(1.0)).Return(nil)
	stats.Gauge("gauge", 2)
	statter.EXPECT().GaugeDelta("fake.delta", int64(2), float32(1.0)).Return(nil)
	stats.GaugeDelta("delta", 2)
	statter.EXPECT().Timing("fake.latency", int64(2), float32(1.0)).Return(nil)
	stats.Timing("latency", 2)
	statter.EXPECT().TimingDuration("fake.latency", 2*time.Second, float32(1.0)).Return(nil)
	stats.TimingDuration("latency", 2*time.Second)
	statter.EXPECT().Set("fake.something", "value", float32(1.0)).Return(nil)
	stats.Set("something", "value")
	statter.EXPECT().SetInt("fake.someint", int64(10), float32(1.0)).Return(nil)
	stats.SetInt("someint", 10)
	statter.EXPECT().Raw("fake.raw", "raw value", float32(1.0)).Return(nil)
	stats.Raw("raw", "raw value")

	s := stats.NewScope("foobar")
	statter.EXPECT().Inc("fake.foobar.counter", int64(3), float32(1.0)).Return(nil)
	s.Inc("counter", 3)
	ss := stats.NewScope("another", "level")
	statter.EXPECT().Inc("fake.foobar.counter", int64(4), float32(1.0)).Return(nil)
	s.Inc("counter", 4)

	if stats.Scope() != "fake" {
		t.Errorf(`expected "fake", got %#v`, stats.Scope())
	}
	if s.Scope() != "fake.foobar" {
		t.Errorf(`expected "fake.foobar", got %#v`, s.Scope())
	}
	if ss.Scope() != "fake.another.level" {
		t.Errorf(`expected "fake.foobar", got %#v`, s.Scope())
	}

	twoScope := NewStatsdScope(statter, "fake", "bang")
	statter.EXPECT().Inc("fake.bang.counter", int64(7), float32(1.0)).Return(nil)
	twoScope.Inc("counter", 7)

}
