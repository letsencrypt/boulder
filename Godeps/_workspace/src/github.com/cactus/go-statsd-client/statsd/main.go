package statsd

import (
	"bytes"
	"errors"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"time"
)

type Statter interface {
	Inc(stat string, value int64, rate float32) error
	Dec(stat string, value int64, rate float32) error
	Gauge(stat string, value int64, rate float32) error
	GaugeDelta(stat string, value int64, rate float32) error
	Timing(stat string, delta int64, rate float32) error
	TimingDuration(stat string, delta time.Duration, rate float32) error
	Set(stat string, value string, rate float32) error
	SetInt(stat string, value int64, rate float32) error
	Raw(stat string, value string, rate float32) error
	SetPrefix(prefix string)
	Close() error
}

type Sender interface {
	Send(data []byte) (int, error)
	Close() error
}

type Client struct {
	// prefix for statsd name
	prefix string
	// sync.Pool of bytes.Buffer
	bytePool *sync.Pool
	// packet sender
	sender Sender
}

// Close closes the connection and cleans up.
func (s *Client) Close() error {
	if s == nil {
		return nil
	}
	err := s.sender.Close()
	return err
}

// Increments a statsd count type.
// stat is a string name for the metric.
// value is the integer value
// rate is the sample rate (0.0 to 1.0)
func (s *Client) Inc(stat string, value int64, rate float32) error {
	if !s.includeStat(rate) {
		return nil
	}
	dap := strconv.FormatInt(value, 10) + "|c"
	return s.submit(stat, dap, rate)
}

// Decrements a statsd count type.
// stat is a string name for the metric.
// value is the integer value.
// rate is the sample rate (0.0 to 1.0).
func (s *Client) Dec(stat string, value int64, rate float32) error {
	if !s.includeStat(rate) {
		return nil
	}
	return s.Inc(stat, -value, rate)
}

// Submits/Updates a statsd gauge type.
// stat is a string name for the metric.
// value is the integer value.
// rate is the sample rate (0.0 to 1.0).
func (s *Client) Gauge(stat string, value int64, rate float32) error {
	if !s.includeStat(rate) {
		return nil
	}
	dap := strconv.FormatInt(value, 10) + "|g"
	return s.submit(stat, dap, rate)
}

// Submits a delta to a statsd gauge.
// stat is the string name for the metric.
// value is the (positive or negative) change.
// rate is the sample rate (0.0 to 1.0).
func (s *Client) GaugeDelta(stat string, value int64, rate float32) error {
	if !s.includeStat(rate) {
		return nil
	}

	prefix := ""
	if value >= 0 {
		prefix = "+"
	}
	dap := prefix + strconv.FormatInt(value, 10) + "|g"
	return s.submit(stat, dap, rate)
}

// Submits a statsd timing type.
// stat is a string name for the metric.
// delta is the time duration value in milliseconds
// rate is the sample rate (0.0 to 1.0).
func (s *Client) Timing(stat string, delta int64, rate float32) error {
	if !s.includeStat(rate) {
		return nil
	}
	dap := strconv.FormatInt(delta, 10) + "|ms"
	return s.submit(stat, dap, rate)
}

// Submits a statsd timing type.
// stat is a string name for the metric.
// delta is the timing value as time.Duration
// rate is the sample rate (0.0 to 1.0).
func (s *Client) TimingDuration(stat string, delta time.Duration, rate float32) error {
	if !s.includeStat(rate) {
		return nil
	}
	ms := float64(delta) / float64(time.Millisecond)
	//dap := fmt.Sprintf("%.02f|ms", ms)
	dap := strconv.FormatFloat(ms, 'f', -1, 64) + "|ms"
	return s.submit(stat, dap, rate)
}

// Submits a stats set type
// stat is a string name for the metric.
// value is the string value
// rate is the sample rate (0.0 to 1.0).
func (s *Client) Set(stat string, value string, rate float32) error {
	if !s.includeStat(rate) {
		return nil
	}
	dap := value + "|s"
	return s.submit(stat, dap, rate)
}

// Submits a number as a stats set type.
// stat is a string name for the metric.
// value is the integer value
// rate is the sample rate (0.0 to 1.0).
func (s *Client) SetInt(stat string, value int64, rate float32) error {
	if !s.includeStat(rate) {
		return nil
	}
	dap := strconv.FormatInt(value, 10) + "|s"
	return s.submit(stat, dap, rate)
}

// Raw submits a preformatted value.
// stat is the string name for the metric.
// value is a preformatted "raw" value string.
// rate is the sample rate (0.0 to 1.0).
func (s *Client) Raw(stat string, value string, rate float32) error {
	if !s.includeStat(rate) {
		return nil
	}
	return s.submit(stat, value, rate)
}

func (s *Client) getBuffer() *bytes.Buffer {
	if s.bytePool == nil {
		return &bytes.Buffer{}
	}
	buf := s.bytePool.Get().(*bytes.Buffer)
	buf.Reset()
	return buf
}

func (s *Client) putBuffer(buf *bytes.Buffer) {
	if s.bytePool == nil {
		return
	}
	s.bytePool.Put(buf)
	return
}

// submit an already sampled raw stat
func (s *Client) submit(stat string, value string, rate float32) error {
	if s == nil {
		return nil
	}

	data := s.getBuffer()
	if s.prefix != "" {
		data.WriteString(s.prefix + ".")
	}
	data.WriteString(stat + ":" + value)

	if rate < 1 {
		data.WriteString("|@")
		data.WriteString(strconv.FormatFloat(float64(rate), 'f', 6, 32))
	}

	d := data.Bytes()
	_, err := s.sender.Send(d)
	if err != nil {
		return err
	}
	return nil
}

// check for nil client, and perform sampling calculation
func (s *Client) includeStat(rate float32) bool {
	if s == nil {
		return false
	}

	if rate < 1 {
		if rand.Float32() < rate {
			return true
		}
		return false
	}
	return true
}

// Sets/Updates the statsd client prefix.
func (s *Client) SetPrefix(prefix string) {
	if s == nil {
		return
	}
	s.prefix = prefix
}

// SimpleSender provides a socket send interface.
type SimpleSender struct {
	// underlying connection
	c net.PacketConn
	// resolved udp address
	ra *net.UDPAddr
}

// Send sends the data to the server endpoint.
func (s *SimpleSender) Send(data []byte) (int, error) {
	// no need for locking here, as the underlying fdNet
	// already serialized writes
	n, err := s.c.(*net.UDPConn).WriteToUDP(data, s.ra)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return n, errors.New("Wrote no bytes")
	}
	return n, nil
}

// Closes SimpleSender
func (s *SimpleSender) Close() error {
	err := s.c.Close()
	return err
}

// Returns a new SimpleSender for sending to the supplied addresss.
//
// addr is a string of the format "hostname:port", and must be parsable by
// net.ResolveUDPAddr.
func NewSimpleSender(addr string) (Sender, error) {
	c, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, err
	}

	ra, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	sender := &SimpleSender{
		c:  c,
		ra: ra,
	}

	return sender, nil
}

// Returns a pointer to a new Client, and an error.
//
// addr is a string of the format "hostname:port", and must be parsable by
// net.ResolveUDPAddr.
//
// prefix is the statsd client prefix. Can be "" if no prefix is desired.
func NewClient(addr, prefix string) (Statter, error) {
	sender, err := NewSimpleSender(addr)
	if err != nil {
		return nil, err
	}

	client := &Client{
		prefix:   prefix,
		bytePool: &sync.Pool{New: func() interface{} { return &bytes.Buffer{} }},
		sender:   sender,
	}

	return client, nil
}

// Compatibility alias
var Dial = New
var New = NewClient
