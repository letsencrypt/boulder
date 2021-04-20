package hnynethttp

import (
	"context"
	"net/http"
	"reflect"
	"runtime"

	"github.com/honeycombio/beeline-go/propagation"
	"github.com/honeycombio/beeline-go/timer"
	"github.com/honeycombio/beeline-go/trace"
	"github.com/honeycombio/beeline-go/wrappers/common"
	"github.com/honeycombio/beeline-go/wrappers/config"
	libhoney "github.com/honeycombio/libhoney-go"
)

// WrapHandlerWithConfig will create a Honeycomb event per invocation
// of this handler with all the standard HTTP fields attached. If passed a
// ServeMux instead, pull what you can from there. The provided config has a
// HTTPTraceParserHook, it will be invoked when creating a new span or trace for
// each incoming HTTP request.
func WrapHandlerWithConfig(handler http.Handler, cfg config.HTTPIncomingConfig) http.Handler {
	// if we can cache handlerName here, let's do so for efficiency's sake
	handlerName := runtime.FuncForPC(reflect.ValueOf(handler).Pointer()).Name()

	wrappedHandler := func(w http.ResponseWriter, r *http.Request) {
		// get a new context with our trace from the request, and add common fields
		var ctx context.Context
		var span *trace.Span
		if cfg.HTTPParserHook == nil {
			ctx, span = common.StartSpanOrTraceFromHTTP(r)
		} else {
			ctx, span = common.StartSpanOrTraceFromHTTPWithTraceParserHook(r, cfg.HTTPParserHook)
		}
		defer span.Send()
		// push the context with our trace and span on to the request
		r = r.WithContext(ctx)
		// replace the writer with our wrapper to catch the status code
		wrappedWriter := common.NewResponseWriter(w)

		mux, ok := handler.(*http.ServeMux)
		if ok {
			// this is actually a mux! let's do extra muxxy stuff
			handler, pat := mux.Handler(r)
			name := runtime.FuncForPC(reflect.ValueOf(handler).Pointer()).Name()
			hType := reflect.TypeOf(handler).String()
			span.AddField("handler.pattern", pat)
			span.AddField("handler.type", hType)
			if name != "" {
				span.AddField("handler.name", name)
				span.AddField("name", name)
			}
		} else {
			if handlerName != "" {
				span.AddField("handler.name", handlerName)
				span.AddField("name", handlerName)
			} else {
				// we always want a name, even if it's kinda useless.
				span.AddField("name", "handler")
			}
		}

		handler.ServeHTTP(wrappedWriter.Wrapped, r)
		if wrappedWriter.Status == 0 {
			wrappedWriter.Status = 200
		}
		if cl := wrappedWriter.Wrapped.Header().Get("Content-Length"); cl != "" {
			span.AddField("response.content_length", cl)
		}
		if ct := wrappedWriter.Wrapped.Header().Get("Content-Type"); ct != "" {
			span.AddField("response.content_type", ct)
		}
		if ce := wrappedWriter.Wrapped.Header().Get("Content-Encoding"); ce != "" {
			span.AddField("response.content_encoding", ce)
		}
		span.AddField("response.status_code", wrappedWriter.Status)
	}
	return http.HandlerFunc(wrappedHandler)
}

// WrapHandler will create a Honeycomb event per invocation of this handler with
// all the standard HTTP fields attached. If passed a ServeMux instead, pull
// what you can from there
func WrapHandler(handler http.Handler) http.Handler {
	return WrapHandlerWithConfig(handler, config.HTTPIncomingConfig{})
}

// WrapHandlerFunc will create a Honeycomb event per invocation of this handler
// function with all the standard HTTP fields attached.
func WrapHandlerFunc(hf func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	handlerFuncName := runtime.FuncForPC(reflect.ValueOf(hf).Pointer()).Name()
	return func(w http.ResponseWriter, r *http.Request) {
		// get a new context with our trace from the request, and add common fields
		ctx, span := common.StartSpanOrTraceFromHTTP(r)
		defer span.Send()
		// push the context with our trace and span on to the request
		r = r.WithContext(ctx)
		// replace the writer with our wrapper to catch the status code
		wrappedWriter := common.NewResponseWriter(w)
		// add the name of the handler func we're about to invoke
		if handlerFuncName != "" {
			span.AddField("handler_func_name", handlerFuncName)
			span.AddField("name", handlerFuncName)
		}

		hf(wrappedWriter.Wrapped, r)
		if wrappedWriter.Status == 0 {
			wrappedWriter.Status = 200
		}
		if cl := wrappedWriter.Wrapped.Header().Get("Content-Length"); cl != "" {
			span.AddField("response.content_length", cl)
		}
		if ct := wrappedWriter.Wrapped.Header().Get("Content-Type"); ct != "" {
			span.AddField("response.content_type", ct)
		}
		if ce := wrappedWriter.Wrapped.Header().Get("Content-Encoding"); ce != "" {
			span.AddField("response.content_encoding", ce)
		}
		span.AddField("response.status_code", wrappedWriter.Status)
	}
}

type hnyTripper struct {
	// wrt is the wrapped round tripper
	wrt             http.RoundTripper
	propagationHook config.HTTPTracePropagationHook
}

func (ht *hnyTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	ctx := r.Context()
	span := trace.GetSpanFromContext(ctx)
	if span == nil {
		return ht.eventRoundTrip(r)
	}
	return ht.spanRoundTrip(ctx, span, r)
}

func (ht *hnyTripper) eventRoundTrip(r *http.Request) (*http.Response, error) {
	// if there's no trace in the context, just send an event
	tm := timer.Start()
	ev := libhoney.NewEvent()
	defer ev.Send()

	// add in common request headers.
	for k, v := range common.GetRequestProps(r) {
		ev.AddField(k, v)
	}

	ev.AddField("meta.type", "http_client")

	resp, err := ht.wrt.RoundTrip(r)

	if err != nil {
		// TODO should this error field be namespaced somehow
		ev.AddField("error", err.Error())
	}
	dur := tm.Finish()
	ev.AddField("duration_ms", dur)
	return resp, err

}

func (ht *hnyTripper) spanRoundTrip(ctx context.Context, span *trace.Span, r *http.Request) (*http.Response, error) {
	// we have a trace, let's use it and pass along trace context in addition to
	// making a span around this HTTP call
	ctx, span = span.CreateChild(ctx)
	defer span.Send()

	r = r.WithContext(ctx)
	// add in common request headers.
	for k, v := range common.GetRequestProps(r) {
		span.AddField(k, v)
	}
	span.AddField("meta.type", "http_client")
	span.AddField("name", "http_client")
	// If no propagation hook is defined, default to using the Honeycomb header format.
	if ht.propagationHook == nil {
		r.Header.Add(propagation.TracePropagationHTTPHeader, span.SerializeHeaders())
	} else {
		// if a propagationHook exists, call it to get a map of headers to
		// inject in the outgoing request.
		headers := ht.propagationHook(r, span.PropagationContext())
		for header, value := range headers {
			r.Header.Add(header, value)
		}
	}

	resp, err := ht.wrt.RoundTrip(r)

	if err != nil {
		// TODO should this error field be namespaced somehow
		span.AddField("error", err.Error())
	} else {
		if cl := resp.Header.Get("Content-Length"); cl != "" {
			span.AddField("response.content_length", cl)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "" {
			span.AddField("response.content_type", ct)
		}
		if ce := resp.Header.Get("Content-Encoding"); ce != "" {
			span.AddField("response.content_encoding", ce)
		}
		span.AddField("response.status_code", resp.StatusCode)
	}
	return resp, err
}

// WrapRoundTripper wraps an http transport for outgoing HTTP calls. Using a
// wrapped transport will send an event to Honeycomb for each outbound HTTP call
// you make. Include a context with outbound requests when possible to enable
// correlation
func WrapRoundTripper(r http.RoundTripper) http.RoundTripper {
	return &hnyTripper{
		wrt: r,
	}
}

// WrapRoundTripperWithConfig is a version of WrapRoundTripper that accepts a config.
// If the config contains a HTTPTracePropagationHook, it will be invoked on each outgoing
// HTTP call. The return value, a map of header names to header strings, will be added
// to the headers of the outgoing request.
func WrapRoundTripperWithConfig(r http.RoundTripper, cfg config.HTTPOutgoingConfig) http.RoundTripper {
	tripper := &hnyTripper{wrt: r}
	if cfg.HTTPPropagationHook != nil {
		tripper.propagationHook = cfg.HTTPPropagationHook
	}
	return tripper
}
