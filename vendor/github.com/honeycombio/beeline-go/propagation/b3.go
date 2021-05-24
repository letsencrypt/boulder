package propagation

import (
	"context"
	"fmt"

	"go.opentelemetry.io/contrib/propagators/b3"
	"go.opentelemetry.io/otel/trace"
)

// MarshalB3TraceContext uses the information in prop to create trace context headers
// that conform to the B3 Trace Context specification. The header values are set in headers,
// which is an HTTPSupplier, an interface to which http.Header is an implementation. The headers
// are also returned as a map[string]string.
//
// Context is passed into this function and returned so that we can maintain the value of the
// tracestate header. This is required in order to use the Propagator interface exported by the
// OpenTelemetry Go SDK and avoid writing our own B3 Trace Context parser and serializer.
//
// If prop is empty or nil, the return value will be an empty map.
func MarshalB3TraceContext(ctx context.Context, prop *PropagationContext) (context.Context, map[string]string) {
	headerMap := make(map[string]string)
	otelSpan, err := createOpenTelemetrySpan(prop)
	if err != nil {
		return ctx, headerMap
	}
	ctx = trace.ContextWithSpan(ctx, otelSpan)
	propagator := b3.B3{InjectEncoding: b3.B3MultipleHeader}
	supp := supplier{
		values: make(map[string]string),
	}
	propagator.Inject(ctx, supp)
	for _, key := range propagator.Fields() {
		headerMap[key] = supp.Get(key)
	}
	return ctx, headerMap
}

// UnmarshalB3TraceContext parses the information provided in the appropriate headers
// and creates a PropagationContext instance. Headers are passed in via an HTTPSupplier,
// which is an interface that defines Get and Set methods, http.Header is an implementation.
//
// Context is passed into this function and returned so that we can maintain the value of the
// tracestate header. This is required in order to use the Propagator interface exported by the
// OpenTelemetry Go SDK and avoid writing our own B3 Trace Context parser and serializer.
//
// If the headers contain neither a trace id or parent id, an error will be returned.
func UnmarshalB3TraceContext(ctx context.Context, headers map[string]string) (context.Context, *PropagationContext, error) {
	supp := supplier{
		values: headers,
	}
	propagator := b3.B3{}
	ctx = propagator.Extract(ctx, supp)
	spanContext := trace.RemoteSpanContextFromContext(ctx)
	prop := &PropagationContext{
		TraceID:    spanContext.TraceID().String(),
		ParentID:   spanContext.SpanID().String(),
		TraceFlags: spanContext.TraceFlags(),
	}
	if !prop.IsValid() {
		return ctx, nil, &PropagationError{
			fmt.Sprintf("Could not parse headers into propagation context: %+v", headers),
			nil,
		}
	}
	return ctx, prop, nil
}
