package web

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/context"

	blog "github.com/letsencrypt/boulder/log"
)

type RequestEvent struct {
	// These fields are not rendered in JSON; instead, they are rendered
	// whitespace-separated ahead of the JSON. This saves bytes in the logs since
	// we don't have to include field names, quotes, or commas -- all of these
	// fields are known to not include whitespace.
	Method    string  `json:"-"`
	Endpoint  string  `json:"-"`
	Requester int64   `json:"-"`
	Code      int     `json:"-"`
	Latency   float64 `json:"-"`
	RealIP    string  `json:"-"`

	Slug           string                 `json:",omitempty"`
	InternalErrors []string               `json:",omitempty"`
	Error          string                 `json:",omitempty"`
	Contacts       []string               `json:",omitempty"`
	UserAgent      string                 `json:"ua,omitempty"`
	Payload        string                 `json:",omitempty"`
	Extra          map[string]interface{} `json:",omitempty"`

	// For endpoints that create objects, the ID of the newly created object.
	Created string `json:",omitempty"`

	// For challenge and authorization GETs and POSTs:
	// the status of the authorization at the time the request began.
	Status string `json:",omitempty"`
	// The DNS name, if applicable
	DNSName string `json:",omitempty"`

	// For challenge POSTs, the challenge type.
	ChallengeType string `json:",omitempty"`
}

func (e *RequestEvent) AddError(msg string, args ...interface{}) {
	e.InternalErrors = append(e.InternalErrors, fmt.Sprintf(msg, args...))
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

// responseWriterWithStatus satisfies http.ResponseWriter, but keeps track of the
// status code for logging.
type responseWriterWithStatus struct {
	http.ResponseWriter
	code int
}

// WriteHeader stores a status code for generating stats.
func (r *responseWriterWithStatus) WriteHeader(code int) {
	r.code = code
	r.ResponseWriter.WriteHeader(code)
}

func (th *TopHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check that this header is well-formed, since we assume it is when logging.
	realIP := r.Header.Get("X-Real-IP")
	if net.ParseIP(realIP) == nil {
		realIP = "0.0.0.0"
	}

	logEvent := &RequestEvent{
		RealIP:    realIP,
		Method:    r.Method,
		UserAgent: r.Header.Get("User-Agent"),
		Extra:     make(map[string]interface{}, 0),
	}

	begin := time.Now()
	rwws := &responseWriterWithStatus{w, 0}
	defer func() {
		logEvent.Code = rwws.code
		logEvent.Latency = time.Since(begin).Seconds()
		th.logEvent(logEvent)
	}()
	th.wfe.ServeHTTP(logEvent, rwws, r)
}

func (th *TopHandler) logEvent(logEvent *RequestEvent) {
	var msg string
	jsonEvent, err := json.Marshal(logEvent)
	if err != nil {
		th.log.AuditErrf("failed to marshal logEvent - %s - %#v", msg, err)
		return
	}
	th.log.Infof("%s %s %d %d %d %s JSON=%s",
		logEvent.Method, logEvent.Endpoint, logEvent.Requester, logEvent.Code,
		int(logEvent.Latency*1000), logEvent.RealIP, jsonEvent)
}

// GetClientAddr: Comma-separated list of HTTP clients involved in making this
// request, starting with the original requestor and ending with the
// remote end of our TCP connection (which is typically our own
// proxy).
func GetClientAddr(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff + "," + r.RemoteAddr
	}
	return r.RemoteAddr
}
