package web

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/letsencrypt/boulder/blog"
)

// errorWriter is an adaptor for blog.Logger to meet the io.Writer interface,
// used by the go stdlib's log.Logger, which in turn is used by http.Server.
// It appears here rather than in //blog/adapters.go because it is used
// locally, not set at a package-global level.
type errorWriter struct {
	blog.Logger
}

func (ew errorWriter) Write(p []byte) (int, error) {
	// log.Logger appends a newline to all messages before calling Write. Our
	// logging infra will append another. Strip the first one to prevent
	// redundancy.
	p = bytes.TrimRight(p, "\n")
	ew.Logger.Error(context.Background(), "net/http.Server", errors.New(string(p)))
	return len(p), nil
}

// NewServer returns an http.Server which will listen on the given address, when
// started, for each path in the handler. Errors are sent to the given logger.
func NewServer(listenAddr string, handler http.Handler, logger blog.Logger) http.Server {
	return http.Server{
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
		Addr:         listenAddr,
		ErrorLog:     log.New(errorWriter{logger}, "", 0),
		Handler:      handler,
	}
}
