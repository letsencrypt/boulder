package statsd

import (
	"bytes"
	"fmt"
	"sync"
	"time"
)

// BufferedSender provides a buffered statsd udp, sending multiple
// metrics, where possible.
type BufferedSender struct {
	flushBytes    int
	flushInterval time.Duration
	sender        Sender
	buffer        *bytes.Buffer
	reqs          chan []byte
	shutdown      chan chan error
	running       bool
	mx            sync.RWMutex
}

// Send bytes.
func (s *BufferedSender) Send(data []byte) (int, error) {
	s.mx.RLock()
	defer s.mx.RUnlock()
	if !s.running {
		return 0, fmt.Errorf("BufferedSender is not running")
	}

	// copy bytes, because the caller may mutate the slice (and the underlying
	// array) after we return, since we may not end up sending right away.
	c := make([]byte, len(data))
	dlen := copy(c, data)
	s.reqs <- c
	return dlen, nil
}

// Close Buffered Sender
func (s *BufferedSender) Close() error {
	// only need really read lock to see if we are currently
	// running or not
	s.mx.RLock()
	if !s.running {
		s.mx.RUnlock()
		return nil
	}
	s.mx.RUnlock()

	// since we are running, write lock during cleanup
	s.mx.Lock()
	defer s.mx.Unlock()

	errChan := make(chan error)
	s.running = false
	s.shutdown <- errChan
	return <-errChan
}

// Start Buffered Sender
// Begins ticker and read loop
func (s *BufferedSender) Start() {
	// read lock to see if we are running
	s.mx.RLock()
	if s.running {
		s.mx.RUnlock()
		return
	}
	s.mx.RUnlock()

	// write lock to start running
	s.mx.Lock()
	defer s.mx.Unlock()
	s.running = true
	s.reqs = make(chan []byte, 8)
	go s.run()
}

func (s *BufferedSender) run() {
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if s.buffer.Len() > 0 {
				s.flush()
			}
		case req := <-s.reqs:
			// StatsD supports receiving multiple metrics in a single packet by
			// separating them with a newline.
			if s.buffer.Len()+len(req)+1 > s.flushBytes {
				s.flush()
			}
			s.buffer.Write(req)
			s.buffer.WriteByte('\n')

			// if we happen to fill up the buffer, just flush right away
			// instead of waiting for next input.
			if s.buffer.Len() >= s.flushBytes {
				s.flush()
			}
		case errChan := <-s.shutdown:
			close(s.reqs)
			for req := range s.reqs {
				if s.buffer.Len()+len(req)+1 > s.flushBytes {
					s.flush()
				}
				s.buffer.Write(req)
				s.buffer.WriteByte('\n')
			}

			if s.buffer.Len() > 0 {
				s.flush()
			}
			errChan <- s.sender.Close()
			return
		}
	}

}

// flush the buffer/send to remove endpoint.
func (s *BufferedSender) flush() (int, error) {
	n, err := s.sender.Send(bytes.TrimSuffix(s.buffer.Bytes(), []byte("\n")))
	s.buffer.Reset() // clear the buffer
	return n, err
}

// Returns a new BufferedSender
//
// addr is a string of the format "hostname:port", and must be parsable by
// net.ResolveUDPAddr.
//
// flushInterval is a time.Duration, and specifies the maximum interval for
// packet sending. Note that if you send lots of metrics, you will send more
// often. This is just a maximal threshold.
//
// flushBytes specifies the maximum udp packet size you wish to send. If adding
// a metric would result in a larger packet than flushBytes, the packet will
// first be send, then the new data will be added to the next packet.
func NewBufferedSender(addr string, flushInterval time.Duration, flushBytes int) (Sender, error) {
	simpleSender, err := NewSimpleSender(addr)
	if err != nil {
		return nil, err
	}

	sender := &BufferedSender{
		flushBytes:    flushBytes,
		flushInterval: flushInterval,
		sender:        simpleSender,
		buffer:        bytes.NewBuffer(make([]byte, 0, flushBytes)),
		shutdown:      make(chan chan error),
	}

	sender.Start()
	return sender, nil
}
