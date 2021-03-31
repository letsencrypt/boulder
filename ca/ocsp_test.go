package ca

import (
	"encoding/hex"
	"testing"
	"time"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
	"golang.org/x/crypto/ocsp"
)

func serial(t *testing.T) []byte {
	serial, err := hex.DecodeString("aabbccddeeffaabbccddeeff000102030405")
	if err != nil {
		t.Fatal(err)
	}
	return serial

}

// Set up an ocspLogQueue with a very long period and a large maxLen,
// to ensure any buffered entries get flushed on `.stop()`.
func TestOcspLogFlushOnExit(t *testing.T) {
	t.Parallel()
	log := blog.NewMock()
	stats := metrics.NoopRegisterer
	queue := newOCSPLogQueue(4000, 10000*time.Millisecond, stats, log)
	go queue.loop()
	queue.enqueue(serial(t), time.Now(), ocsp.ResponseStatus(ocsp.Good))
	queue.stop()

	expected := []string{
		"INFO: [AUDIT] OCSP signed: aabbccddeeffaabbccddeeff000102030405:0,",
	}
	test.AssertDeepEquals(t, log.GetAll(), expected)
}

// Ensure log lines are sent when they exceed maxLen.
func TestOcspFlushOnLength(t *testing.T) {
	t.Parallel()
	log := blog.NewMock()
	stats := metrics.NoopRegisterer
	queue := newOCSPLogQueue(100, 100*time.Millisecond, stats, log)
	go queue.loop()
	for i := 0; i < 5; i++ {
		queue.enqueue(serial(t), time.Now(), ocsp.ResponseStatus(ocsp.Good))
	}
	queue.stop()

	expected := []string{
		"INFO: [AUDIT] OCSP signed: aabbccddeeffaabbccddeeff000102030405:0,aabbccddeeffaabbccddeeff000102030405:0,",
		"INFO: [AUDIT] OCSP signed: aabbccddeeffaabbccddeeff000102030405:0,aabbccddeeffaabbccddeeff000102030405:0,",
		"INFO: [AUDIT] OCSP signed: aabbccddeeffaabbccddeeff000102030405:0,",
	}
	test.AssertDeepEquals(t, log.GetAll(), expected)
}

// Ensure log lines are sent after a timeout.
func TestOcspFlushOnTimeout(t *testing.T) {
	t.Parallel()
	log := blog.NewWaitingMock()
	stats := metrics.NoopRegisterer
	queue := newOCSPLogQueue(90000, 10*time.Millisecond, stats, log)

	go queue.loop()
	queue.enqueue(serial(t), time.Now(), ocsp.ResponseStatus(ocsp.Good))

	expected := "INFO: [AUDIT] OCSP signed: aabbccddeeffaabbccddeeff000102030405:0,"
	logLines, err := log.WaitForMatch("OCSP signed", 50*time.Millisecond)
	test.AssertNotError(t, err, "error in mock log")
	test.AssertDeepEquals(t, logLines, expected)
	queue.stop()
}

// If the deadline passes and nothing has been logged, we should not log a blank line.
func TestOcspNoEmptyLines(t *testing.T) {
	t.Parallel()
	log := blog.NewMock()
	stats := metrics.NoopRegisterer
	queue := newOCSPLogQueue(90000, 10*time.Millisecond, stats, log)

	go queue.loop()
	time.Sleep(50 * time.Millisecond)
	queue.stop()

	test.AssertDeepEquals(t, log.GetAll(), []string{})
}

// If the maxLogLen is shorter than one entry, log everything immediately.
func TestOcspLogWhenMaxLogLenIsShort(t *testing.T) {
	t.Parallel()
	log := blog.NewMock()
	stats := metrics.NoopRegisterer
	queue := newOCSPLogQueue(3, 10000*time.Millisecond, stats, log)
	go queue.loop()
	queue.enqueue(serial(t), time.Now(), ocsp.ResponseStatus(ocsp.Good))
	queue.stop()

	expected := []string{
		"INFO: [AUDIT] OCSP signed: aabbccddeeffaabbccddeeff000102030405:0,",
	}
	test.AssertDeepEquals(t, log.GetAll(), expected)
}

// Enqueueing entries after stop causes panic.
func TestOcspLogPanicsOnEnqueueAfterStop(t *testing.T) {
	t.Parallel()

	log := blog.NewMock()
	stats := metrics.NoopRegisterer
	queue := newOCSPLogQueue(4000, 10000*time.Millisecond, stats, log)
	go queue.loop()
	queue.stop()

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()

	queue.enqueue(serial(t), time.Now(), ocsp.ResponseStatus(ocsp.Good))
}
