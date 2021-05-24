package propagation

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// MarshalHoneycombTraceContext uses the information in prop to create trace context headers
// that conform to the W3C Trace Context specification. The header values are set in headers,
// which is an HTTPSupplier, an interface to which http.Header is an implementation. The headers
// are also returned as a map[string]string.
//
// Context is passed into this function and returned so that we can maintain the value of the
// tracestate header. This is required in order to use the Propagator interface exported by the
// OpenTelemetry Go SDK and avoid writing our own W3C Trace Context parser and serializer.
//
// If prop is empty or nil, the return value will be an empty map.
func MarshalW3CTraceContext(ctx context.Context, prop *PropagationContext) (context.Context, map[string]string) {
	headerMap := make(map[string]string)
	otelSpan, err := createOpenTelemetrySpan(prop)
	if err != nil {
		return ctx, headerMap
	}
	ctx = trace.ContextWithSpan(ctx, otelSpan)
	propagator := propagation.TraceContext{}
	supp := supplier{
		values: make(map[string]string),
	}
	propagator.Inject(ctx, supp)
	for _, key := range propagator.Fields() {
		headerMap[key] = supp.Get(key)
	}
	return ctx, headerMap
}

// UnmarshalW3CTraceContext parses the information provided in the appropriate headers
// and creates a PropagationContext instance. Headers are passed in via an HTTPSupplier,
// which is an interface that defines Get and Set methods, http.Header is an implementation.
//
// Context is passed into this function and returned so that we can maintain the value of the
// tracestate header. This is required in order to use the Propagator interface exported by the
// OpenTelemetry Go SDK and avoid writing our own W3C Trace Context parser and serializer.
//
// If the headers contain neither a trace id or parent id, an error will be returned.
func UnmarshalW3CTraceContext(ctx context.Context, headers map[string]string) (context.Context, *PropagationContext, error) {
	supp := supplier{
		values: headers,
	}
	propagator := propagation.TraceContext{}
	ctx = propagator.Extract(ctx, supp)
	spanContext := trace.RemoteSpanContextFromContext(ctx)
	prop := &PropagationContext{
		TraceID:    spanContext.TraceID().String(),
		ParentID:   spanContext.SpanID().String(),
		TraceFlags: spanContext.TraceFlags(),
		TraceState: spanContext.TraceState(),
	}
	if !prop.IsValid() {
		return ctx, nil, &PropagationError{
			fmt.Sprintf("Could not parse headers into propagation context: %+v", headers),
			nil,
		}
	}
	return ctx, prop, nil
}

// createOpenTelemetrySpan creates a shell trace.Span with information from the provided
// PropagationContext. It's a shell because the only field populated is the span context.
func createOpenTelemetrySpan(prop *PropagationContext) (trace.Span, error) {
	if prop == nil {
		return otelSpan{}, nil
	}

	traceID, err := trace.TraceIDFromHex(prop.TraceID)
	if err != nil {
		return nil, err
	}
	spanID, err := trace.SpanIDFromHex(prop.ParentID)
	if err != nil {
		return nil, err
	}

	spanCtx := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: prop.TraceFlags,
		TraceState: prop.TraceState,
	})

	return otelSpan{
		ctx: spanCtx,
	}, nil
}

// otelSpan is an implementation of the open telemetry trace.Span interface. We
// want an implementation in order to use the existing otel code for w3c trace
// propagation parsing rather than duplicating that code here. That interface is
// fairly wide, so there are a lot of methods on this type that are noops. The
// only field we need in order to use their trace context propagator is the
// trace.SpanContext, so we populate that.
type otelSpan struct {
	ctx trace.SpanContext
}

// SpanContext returns the trace.SpanContext, which is the only field expected to exist.
func (os otelSpan) SpanContext() trace.SpanContext {
	return os.ctx
}

// IsRecording returns false. It exists to satisfy the trace.Span interface.
func (os otelSpan) IsRecording() bool {
	return false
}

// SetStatus does nothing. It exists to satisfy the trace.Span interface.
func (os otelSpan) SetStatus(code codes.Code, msg string) {
	return
}

// SetAttribute does nothing. It exists to satisfy the trace.Span interface.
func (os otelSpan) SetAttribute(k string, v interface{}) {
	return
}

// SetAttributes does nothing. It exists to satisfy the trace.Span interface.
func (os otelSpan) SetAttributes(attributes ...attribute.KeyValue) {
	return
}

// End does nothing. It exists to satisfy the trace.Span interface.
func (os otelSpan) End(options ...trace.SpanOption) {
	return
}

// RecordError does nothing. It exists to satisfy the trace.Span interface.
func (os otelSpan) RecordError(err error, opts ...trace.EventOption) {
	return
}

// Tracer returns nil. It exists to satisfy the trace.Span interface.
func (os otelSpan) Tracer() trace.Tracer {
	return nil
}

// AddEvent does nothing. It exists to satisfy the trace.Span interface.
func (os otelSpan) AddEvent(name string, options ...trace.EventOption) {
	return
}

// AddEventWithTimestamp does nothing. It exists to satisfy the trace.Span interface.
func (os otelSpan) AddEventWithTimestamp(ctx context.Context, timestamp time.Time, name string, attrs ...attribute.KeyValue) {
	return
}

// SetName does nothing. It exists to satisfy the trace.Span interface.
func (os otelSpan) SetName(name string) {
	return
}

// supplier is a container for values, which is a map of strings to strings. It is intended to
// hold http headers used by the OpenTelemetry SDK. It exists to satisfy the method signatures
// for the opentelemetry sdk but is not part of the beeline trace API.
type supplier struct {
	values map[string]string
}

// Get returns the value associated with the provided key, if any.
func (m supplier) Get(key string) string {
	if value, ok := m.values[key]; ok {
		return value
	}
	return ""
}

// Set associates the provided value with the provided key.
func (m supplier) Set(key string, value string) {
	m.values[key] = value
}

// Keys returns the keys for which this carrier has a value.
func (m supplier) Keys() []string {
	keys := make([]string, 0, len(m.values))

	for k := range m.values {
		keys = append(keys, k)
	}
	return keys
}
