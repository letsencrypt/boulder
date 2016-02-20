package wfe

import (
	"fmt"
	"net/http"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

type requestEvent struct {
	ID            string    `json:",omitempty"`
	RealIP        string    `json:",omitempty"`
	ClientAddr    string    `json:",omitempty"`
	Endpoint      string    `json:",omitempty"`
	Method        string    `json:",omitempty"`
	RequestTime   time.Time `json:",omitempty"`
	ResponseTime  time.Time `json:",omitempty"`
	Errors        []string
	Requester     int64                  `json:",omitempty"`
	Contacts      []*core.AcmeURL        `json:",omitempty"`
	RequestNonce  string                 `json:",omitempty"`
	ResponseNonce string                 `json:",omitempty"`
	UserAgent     string                 `json:",omitempty"`
	Extra         map[string]interface{} `json:",omitempty"`
}

func (e *requestEvent) AddError(msg string, args ...interface{}) {
	e.Errors = append(e.Errors, fmt.Sprintf(msg, args...))
}

type wfeHandlerFunc func(*requestEvent, http.ResponseWriter, *http.Request)

func (f wfeHandlerFunc) ServeHTTP(e *requestEvent, w http.ResponseWriter, r *http.Request) {
	f(e, w, r)
}

type wfeHandler interface {
	ServeHTTP(e *requestEvent, w http.ResponseWriter, r *http.Request)
}

type topHandler struct {
	wfe wfeHandler
	log *blog.AuditLogger
	clk clock.Clock
}

func (th *topHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logEvent := &requestEvent{
		ID:          core.NewToken(),
		RealIP:      r.Header.Get("X-Real-IP"),
		ClientAddr:  getClientAddr(r),
		Method:      r.Method,
		RequestTime: time.Now(),
		UserAgent:   r.Header.Get("User-Agent"),
		Extra:       make(map[string]interface{}, 0),
	}
	if r.URL != nil {
		logEvent.Endpoint = r.URL.String()
	}
	defer th.logEvent(logEvent)

	th.wfe.ServeHTTP(logEvent, w, r)
}

func (th *topHandler) logEvent(logEvent *requestEvent) {
	logEvent.ResponseTime = th.clk.Now()
	var msg string
	if len(logEvent.Errors) != 0 {
		msg = "Terminated request"
	} else {
		msg = "Successful request"
	}
	th.log.InfoObject(msg, logEvent)
}

// Comma-separated list of HTTP clients involved in making this
// request, starting with the original requestor and ending with the
// remote end of our TCP connection (which is typically our own
// proxy).
func getClientAddr(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff + "," + r.RemoteAddr
	}
	return r.RemoteAddr
}
