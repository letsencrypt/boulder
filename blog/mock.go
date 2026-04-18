package blog

import (
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// inmemWriter implements the io.Writer interface, but saves all written bytes
// to an in-memory slice of strings for later inspection.
type inmemWriter struct {
	sync.RWMutex
	out []string
}

func (iw *inmemWriter) Write(p []byte) (int, error) {
	iw.Lock()
	defer iw.Unlock()
	iw.out = append(iw.out, string(p))
	return len(p), nil
}

// Mock implements the blog.Logger interface by virtue of embedding a
// blog.logger which writes to an in-memory datastore. It also exports methods
// allowing callers to inspect all log lines which have been written to it.
type Mock struct {
	*logger
	iw *inmemWriter
}

// NewMock returns an object which implements the blog.Logger interface, but
// which also exposes methods allowing callers to inspect all log lines written
// to it. It always uses the text (i.e. not json) format, and always logs at
// level 7 (debug).
func NewMock() *Mock {
	w := &inmemWriter{out: make([]string, 0)}
	l := slog.New(&contextHandler{inner: newAuditHandler(
		newChecksumWriter(w),
		&slog.HandlerOptions{Level: configToSlogLevel(7)},
	)})
	return &Mock{&logger{inner: l}, w}
}

// GetAll returns all messages logged since instantiation or the last call to
// Clear().
func (ml *Mock) GetAll() []string {
	ml.iw.RLock()
	defer ml.iw.RUnlock()
	return slices.Clone(ml.iw.out)
}

// GetAllMatching returns all messages logged since instantiation or the last
// Clear() whose text matches the given regexp. The regexp is
// accepted as a string and compiled on the fly, because convenience
// is more important than performance.
func (ml *Mock) GetAllMatching(reString string) []string {
	ml.iw.RLock()
	defer ml.iw.RUnlock()

	var matches []string
	re := regexp.MustCompile(reString)
	for _, logMsg := range ml.iw.out {
		if re.MatchString(logMsg) {
			matches = append(matches, logMsg)
		}
	}
	return matches
}

// ExpectMatch returns an error if no log lines matching the given regex have
// been logged since instantiation or the last Clear().
func (ml *Mock) ExpectMatch(reString string) error {
	results := ml.GetAllMatching(reString)
	if len(results) == 0 {
		return fmt.Errorf("expected log line %q, got %q", reString, strings.Join(ml.GetAll(), "\n"))
	}
	return nil
}

// Clear resets the log buffer.
func (ml *Mock) Clear() {
	ml.iw.Lock()
	defer ml.iw.Unlock()
	ml.iw.out = make([]string, 0)
}
