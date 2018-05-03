package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/net/context"

	blog "github.com/letsencrypt/boulder/log"
)

type RequestEvent struct {
	RealIP         string    `json:",omitempty"`
	Endpoint       string    `json:",omitempty"`
	Slug           string    `json:",omitempty"`
	Method         string    `json:",omitempty"`
	InternalErrors []string  `json:",omitempty"`
	Error          string    `json:",omitempty"`
	Requester      int64     `json:",omitempty"`
	Contacts       *[]string `json:",omitempty"`
	UserAgent      string    `json:",omitempty"`
	Latency        float64
	Code           int
	Payload        string                 `json:",omitempty"`
	Extra          map[string]interface{} `json:",omitempty"`
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
	logEvent := &RequestEvent{
		RealIP:    r.Header.Get("X-Real-IP"),
		Method:    r.Method,
		UserAgent: r.Header.Get("User-Agent"),
		Extra:     make(map[string]interface{}, 0),
	}

	begin := time.Now()
	rwws := &responseWriterWithStatus{w, 0}
	defer func() {
		logEvent.Code = rwws.code
		logEvent.Latency = float64(time.Since(begin)) / float64(time.Second)
		th.logEvent(logEvent)
	}()
	th.wfe.ServeHTTP(logEvent, rwws, r)
}

func (th *TopHandler) logEvent(logEvent *RequestEvent) {
	var msg string
	jsonEvent, err := json.Marshal(logEvent)
	if err != nil {
		th.log.AuditErr(fmt.Sprintf("failed to marshal logEvent - %s - %#v", msg, err))
		return
	}
	th.log.Info(fmt.Sprintf("JSON=%s", jsonEvent))
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
