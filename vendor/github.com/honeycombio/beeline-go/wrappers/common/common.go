package common

import (
	"context"
	"database/sql"
	"net/http"
	"runtime"
	"strings"

	"github.com/felixge/httpsnoop"
	"github.com/honeycombio/beeline-go/propagation"
	"github.com/honeycombio/beeline-go/timer"
	"github.com/honeycombio/beeline-go/trace"
	"github.com/honeycombio/beeline-go/wrappers/config"
	libhoney "github.com/honeycombio/libhoney-go"
)

type ResponseWriter struct {
	// Wrapped is not embedded to prevent ResponseWriter from directly
	// fulfilling the http.ResponseWriter interface. Wrapping in this
	// way would obscure optional http.ResponseWriter interfaces.
	Wrapped http.ResponseWriter
	Status  int
}

func NewResponseWriter(w http.ResponseWriter) *ResponseWriter {
	var rw ResponseWriter

	rw.Wrapped = httpsnoop.Wrap(w, httpsnoop.Hooks{
		WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
			return func(code int) {
				// The first call to WriteHeader sends the response header.
				// Any subsequent calls are invalid. Only record the first
				// code written.
				if rw.Status == 0 {
					rw.Status = code
				}
				next(code)
			}
		},
	})

	return &rw
}

// StartSpanOrTraceFromHTTP creates and returns a span for the provided http.Request. If
// there is an existing span in the Context, this function will create the new span as a
// child span and return it. If not, it will create a new trace object and return the root
// span.
func StartSpanOrTraceFromHTTP(r *http.Request) (context.Context, *trace.Span) {
	return StartSpanOrTraceFromHTTPWithTraceParserHook(r, nil)
}

// StartSpanOrTraceFromHTTPWithTraceParserHook is a version of StartSpanOrTraceFromHTTP that
// accepts a TraceParserHook which will be invoked when creating a new trace for the incoming
// HTTP request.
func StartSpanOrTraceFromHTTPWithTraceParserHook(r *http.Request, parserHook config.HTTPTraceParserHook) (context.Context, *trace.Span) {
	ctx := r.Context()
	span := trace.GetSpanFromContext(ctx)
	if span == nil {
		// there is no trace yet. We should make one! and use the root span.
		var tr *trace.Trace
		if parserHook == nil {
			beelineHeader := r.Header.Get(propagation.TracePropagationHTTPHeader)
			prop, _ := propagation.UnmarshalHoneycombTraceContext(beelineHeader)
			ctx, tr = trace.NewTrace(ctx, prop)
		} else {
			// Call the provided TraceParserHook to get the propagation context
			// from the incoming request. This information will then be used when
			// create the new trace.
			prop := parserHook(r)
			ctx, tr = trace.NewTraceFromPropagationContext(ctx, prop)
		}
		span = tr.GetRootSpan()
	} else {
		// we had a parent! let's make a new child for this handler
		ctx, span = span.CreateChild(ctx)
	}
	// go get any common HTTP headers and attributes to add to the span
	for k, v := range GetRequestProps(r) {
		span.AddField(k, v)
	}
	return ctx, span
}

// GetRequestProps is a convenient method to grab all common http request
// properties and get them back as a map.
func GetRequestProps(req *http.Request) map[string]interface{} {
	userAgent := req.UserAgent()
	xForwardedFor := req.Header.Get("x-forwarded-for")
	xForwardedProto := req.Header.Get("x-forwarded-proto")
	host := req.Host
	if host == "" {
		host = req.URL.Hostname()
	}

	reqProps := make(map[string]interface{})
	// identify the type of event
	reqProps["meta.type"] = "http_request"
	// Add a variety of details about the HTTP request, such as user agent
	// and method, to any created libhoney event.
	reqProps["request.method"] = req.Method
	reqProps["request.path"] = req.URL.Path
	if req.URL.RawQuery != "" {
		reqProps["request.query"] = req.URL.RawQuery
	}
	reqProps["request.url"] = req.URL.String()
	reqProps["request.host"] = host
	reqProps["request.http_version"] = req.Proto
	reqProps["request.content_length"] = req.ContentLength
	reqProps["request.remote_addr"] = req.RemoteAddr
	if userAgent != "" {
		reqProps["request.header.user_agent"] = userAgent
	}
	if xForwardedFor != "" {
		reqProps["request.header.x_forwarded_for"] = xForwardedFor
	}
	if xForwardedProto != "" {
		reqProps["request.header.x_forwarded_proto"] = xForwardedProto
	}
	return reqProps
}

// getCallersNames grabs the current call stack, skips up a few levels, then
// grabs as many function names as depth. Suggested use is something like 1, 2
// meaning "get my parent and its parent". skip=0 means the function calling
// this one.
func getCallersNames(skip, depth int) []string {
	callers := make([]string, 0, depth)
	callerPcs := make([]uintptr, depth)
	// add 2 to skip to account for runtime.Callers and getCallersNames
	numCallers := runtime.Callers(skip+2, callerPcs)
	// If there are no callers, the entire stacktrace is nil
	if numCallers == 0 {
		return callers
	}
	callersFrames := runtime.CallersFrames(callerPcs)
	for i := 0; i < depth; i++ {
		fr, more := callersFrames.Next()
		// store the function's name
		nameParts := strings.Split(fr.Function, ".")
		callers = append(callers, nameParts[len(nameParts)-1])
		if !more {
			break
		}
	}
	return callers
}

func sharedDBEvent(bld *libhoney.Builder, query string, args ...interface{}) *libhoney.Event {
	ev := bld.NewEvent()

	// skip 2 - this one and the buildDB*, so we get the sqlx function and its parent
	callerNames := getCallersNames(2, 2)
	switch len(callerNames) {
	case 2:
		ev.AddField("db.call", callerNames[0])
		ev.AddField("name", callerNames[0])
		ev.AddField("db.caller", callerNames[1])
	case 1:
		ev.AddField("db.call", callerNames[0])
		ev.AddField("name", callerNames[0])
	default:
		ev.AddField("name", "db")
	}

	if query != "" {
		ev.AddField("db.query", query)
	}
	if args != nil {
		ev.AddField("db.query_args", args)
	}
	return ev
}

// BuildDBEvent tries to bring together most of the things that need to happen
// for an event to wrap a DB call in both the sql and sqlx packages. It returns a
// function which, when called, dispatches the event that it created. This lets
// it finish a timer around the call automatically. This function is only used
// when no context (and therefore no beeline trace) is available to the caller -
// if context is available, use BuildDBSpan() instead to tie it in to the active
// trace.
func BuildDBEvent(bld *libhoney.Builder, stats sql.DBStats, query string, args ...interface{}) (*libhoney.Event, func(error)) {
	timer := timer.Start()
	ev := sharedDBEvent(bld, query, args)
	addDBStatsToEvent(ev, stats)
	fn := func(err error) {
		duration := timer.Finish()
		// rollup(ctx, ev, duration)
		ev.AddField("duration_ms", duration)
		if err != nil {
			ev.AddField("db.error", err.Error())
		}
		ev.Metadata, _ = ev.Fields()["name"]
		ev.Send()
	}
	return ev, fn
}

// BuildDBSpan does the same things as BuildDBEvent except that it has access to
// a trace from the context and takes advantage of that to add the DB events
// into the trace.
func BuildDBSpan(ctx context.Context, bld *libhoney.Builder, stats sql.DBStats, query string, args ...interface{}) (context.Context, *trace.Span, func(error)) {
	timer := timer.Start()
	parentSpan := trace.GetSpanFromContext(ctx)
	var span *trace.Span
	if parentSpan == nil {
		// if we have no trace, make a new one. This is unfortunate but the
		// least confusing possibility. Would be nice to indicate this had
		// happened in a better way than yet another meta. field.
		var tr *trace.Trace
		ctx, tr = trace.NewTrace(ctx, nil)
		span = tr.GetRootSpan()
		span.AddField("meta.orphaned", true)
	} else {
		ctx, span = parentSpan.CreateChild(ctx)
	}
	addDBStatsToSpan(span, stats)

	ev := sharedDBEvent(bld, query, args...)
	for k, v := range ev.Fields() {
		span.AddField(k, v)
	}
	fn := func(err error) {
		duration := timer.Finish()
		if err != nil {
			span.AddField("db.error", err.Error())
		}
		span.AddRollupField("db.duration_ms", duration)
		span.AddRollupField("db.call_count", 1)
		span.Send()
	}
	return ctx, span, fn
}
