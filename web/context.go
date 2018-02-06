package web

import (
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/net/context"

	blog "github.com/letsencrypt/boulder/log"
)

type RequestEvent struct {
	RealIP    string    `json:",omitempty"`
	Endpoint  string    `json:",omitempty"`
	Method    string    `json:",omitempty"`
	Errors    []string  `json:",omitempty"`
	Requester int64     `json:",omitempty"`
	Contacts  *[]string `json:",omitempty"`
	UserAgent string    `json:",omitempty"`
	Code      int
	Payload   string                 `json:",omitempty"`
	Extra     map[string]interface{} `json:",omitempty"`
}

func (e *RequestEvent) AddError(msg string, args ...interface{}) {
	e.Errors = append(e.Errors, fmt.Sprintf(msg, args...))
}

type WFEHandlerFunc func(context.Context, *RequestEvent, http.ResponseWriter, *http.Request)

func (f WFEHandlerFunc) ServeHTTP(e *RequestEvent, w http.ResponseWriter, r *http.Request) {
	ctx := context.TODO()
	f(ctx, e, w, r)
}

type wfeHandler interface {
	ServeHTTP(e *RequestEvent, w http.ResponseWriter, r *http.Request)
}

type TopHandler struct {
	wfe wfeHandler
	log blog.Logger
}

func NewTopHandler(log blog.Logger, wfe wfeHandler) *TopHandler {
	return &TopHandler{
		wfe: wfe,
		log: log,
	}
}

func (th *TopHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logEvent := &RequestEvent{
		RealIP:    r.Header.Get("X-Real-IP"),
		Method:    r.Method,
		UserAgent: r.Header.Get("User-Agent"),
		Extra:     make(map[string]interface{}, 0),
	}
	defer th.logEvent(logEvent)

	th.wfe.ServeHTTP(logEvent, w, r)
}

func (th *TopHandler) logEvent(logEvent *RequestEvent) {
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
func GetClientAddr(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff + "," + r.RemoteAddr
	}
	return r.RemoteAddr
}
