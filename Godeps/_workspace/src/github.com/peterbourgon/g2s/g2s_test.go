package g2s

import (
	"bytes"
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCounter(t *testing.T) {
	b := &bytes.Buffer{}
	s, err := New(b)
	if err != nil {
		t.Fatal(err)
	}

	s.Counter(1.0, "gorets", 1)

	if expected, got := "gorets:1|c", b.String(); expected != got {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestTiming(t *testing.T) {
	b := &bytes.Buffer{}
	s, err := New(b)
	if err != nil {
		t.Fatal(err)
	}

	s.Timing(1.0, "glork", 320*time.Millisecond)

	if expected, got := "glork:320|ms", b.String(); expected != got {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestGauge(t *testing.T) {
	b := &bytes.Buffer{}
	s, err := New(b)
	if err != nil {
		t.Fatal(err)
	}

	s.Gauge(1.0, "gaugor", "333")

	if expected, got := "gaugor:333|g", b.String(); expected != got {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestMany(t *testing.T) {
	b := &bytes.Buffer{}
	s, err := New(b)
	if err != nil {
		t.Fatal(err)
	}

	s.Counter(1.0, "foo", 1, 2, 3)
	s.Timing(1.0, "bar", 4*time.Millisecond, 5*time.Millisecond)

	expected := "foo:1|c\nfoo:2|c\nfoo:3|cbar:4|ms\nbar:5|ms"
	got := b.String()
	if expected != got {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestSamplingZero(t *testing.T) {
	b := &bytes.Buffer{}
	s, err := New(b)
	if err != nil {
		t.Fatal(err)
	}

	s.Counter(0.0, "nobucket", 1) // should never succeed

	if expected, got := "", b.String(); expected != got {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

type SliceWriter struct {
	data []string
}

func (this *SliceWriter) Write(bytes []byte) (int, error) {
	this.data = append(this.data, string(bytes))
	return len(bytes), nil
}

func TestSampling(t *testing.T) {
	b := &SliceWriter{}
	s, err := New(b)
	if err != nil {
		t.Fatal(err)
	}

	rate, n := float32(0.5), 10000
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < n; i++ {
		s.Counter(rate, "foo", 1)
	}

	middle, threshold := n/2, n/10
	expectedMin, expectedMax := middle-threshold, middle+threshold
	got := b.data

	rateToks := strings.Split(got[0], "@")
	if len(rateToks) != 2 {
		t.Fatalf("splitting packet on '@': expected 2, got %d", len(rateToks))
	}
	gotRate, err := strconv.ParseFloat(rateToks[1], 32)
	if err != nil {
		t.Fatalf("%s: %s", rateToks[1], err)
	}
	if float32(gotRate) != rate {
		t.Errorf("sampling rate: expected %f, got %f", rate, gotRate)
	}

	packetCount := len(got)
	if packetCount < expectedMin || packetCount > expectedMax {
		t.Errorf("got %d packets, but expected between %d and %d", packetCount, expectedMin, expectedMax)
	}

	t.Logf("got %d < %d < %d OK", expectedMin, packetCount, expectedMax)
}
