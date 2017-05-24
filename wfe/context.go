package wfe

import (
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/net/context"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

type requestEvent struct {
	ID            string    `json:",omitempty"`
	RealIP        string    `json:",omitempty"`
	Endpoint      string    `json:",omitempty"`
	Method        string    `json:",omitempty"`
	Errors        []string  `json:",omitempty"`
	Requester     int64     `json:",omitempty"`
	Contacts      *[]string `json:",omitempty"`
	RequestNonce  string    `json:",omitempty"`
	ResponseNonce string    `json:",omitempty"`
	UserAgent     string    `json:",omitempty"`
	Code          int
	Payload       string                 `json:",omitempty"`
	Extra         map[string]interface{} `json:",omitempty"`
}

func (e *requestEvent) AddError(msg string, args ...interface{}) {
	e.Errors = append(e.Errors, fmt.Sprintf(msg, args...))
}

type wfeHandlerFunc func(context.Context, *requestEvent, http.ResponseWriter, *http.Request)

func (f wfeHandlerFunc) ServeHTTP(e *requestEvent, w http.ResponseWriter, r *http.Request) {
	ctx := context.TODO()
	f(ctx, e, w, r)
}

type wfeHandler interface {
	ServeHTTP(e *requestEvent, w http.ResponseWriter, r *http.Request)
}

type topHandler struct {
	wfe wfeHandler
	log blog.Logger
	clk clock.Clock
}

func (th *topHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logEvent := &requestEvent{
		ID:        core.NewToken(),
		RealIP:    r.Header.Get("X-Real-IP"),
		Method:    r.Method,
		UserAgent: r.Header.Get("User-Agent"),
		Extra:     make(map[string]interface{}, 0),
	}
	w.Header().Set("Boulder-Request-ID", logEvent.ID)
	defer th.logEvent(logEvent)

	th.wfe.ServeHTTP(logEvent, w, r)
}

func (th *topHandler) logEvent(logEvent *requestEvent) {
	var msg string
	if len(logEvent.Errors) != 0 {
		msg = "Terminated request"
	} else {
		msg = "Successful request"
	}
	jsonEvent, err := json.Marshal(logEvent)
	if err != nil {
		th.log.AuditErr(fmt.Sprintf("%s - failed to marshal logEvent - %s", msg, err))
		return
	}
	th.log.Info(fmt.Sprintf("%s JSON=%s", msg, jsonEvent))
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
