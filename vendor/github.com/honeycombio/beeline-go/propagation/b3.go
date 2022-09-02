package propagation

import (
	"context"
	"errors"
	"strings"
)

// this file contains functions and types used for parsing and generating B3 headers.
// it mostly contains code based on the implementation found here:
// https://github.com/open-telemetry/opentelemetry-go-contrib/blob/05ef436536dc499361b6c9d3546662a99c2f918f/propagators/b3/b3_propagator.go
// the only exported functions are MarshalB3TraceContext and UnmarshalB3TraceContext

const (
	// Default B3 Header names.
	b3ContextHeader      = "b3"
	b3DebugFlagHeader    = "x-b3-flags"
	b3TraceIDHeader      = "x-b3-traceid"
	b3SpanIDHeader       = "x-b3-spanid"
	b3SampledHeader      = "x-b3-sampled"
	b3ParentSpanIDHeader = "x-b3-parentspanid"

	b3TraceIDPadding = "0000000000000000"

	// B3 Single Header encoding widths.
	separatorWidth      = 1       // Single "-" character.
	samplingWidth       = 1       // Single hex character.
	traceID64BitsWidth  = 64 / 4  // 16 hex character Trace ID.
	traceID128BitsWidth = 128 / 4 // 32 hex character Trace ID.
	spanIDWidth         = 16      // 16 hex character ID.
	parentSpanIDWidth   = 16      // 16 hex character ID.
)

var (
	empty = PropagationContext{}

	errInvalidSampledByte        = errors.New("invalid B3 Sampled found")
	errInvalidSampledHeader      = errors.New("invalid B3 Sampled header found")
	errInvalidTraceIDHeader      = errors.New("invalid B3 traceID header found")
	errInvalidSpanIDHeader       = errors.New("invalid B3 spanID header found")
	errInvalidParentSpanIDHeader = errors.New("invalid B3 ParentSpanID header found")
	errInvalidScope              = errors.New("require either both traceID and spanID or none")
	errInvalidScopeParent        = errors.New("ParentSpanID requires both traceID and spanID to be available")
	errInvalidScopeParentSingle  = errors.New("ParentSpanID requires traceID, spanID and Sampled to be available")
	errEmptyContext              = errors.New("empty request context")
	errInvalidTraceIDValue       = errors.New("invalid B3 traceID value found")
	errInvalidSpanIDValue        = errors.New("invalid B3 spanID value found")
	errInvalidParentSpanIDValue  = errors.New("invalid B3 ParentSpanID value found")
)

// extractMultiple reconstructs a PropagationContext from header values based on B3
// Multiple header. It is based on the implementation found here:
// https://github.com/openzipkin/zipkin-go/blob/v0.2.2/propagation/b3/spancontext.go
// and adapted to support a PropagationContext.
func extractMultiple(ctx context.Context, traceID, spanID, parentSpanID, sampled, flags string) (context.Context, PropagationContext, error) {
	var (
		err           error
		requiredCount int
		prop          = PropagationContext{}
	)

	// correct values for an existing sampled header are "0" and "1".
	// For legacy support and  being lenient to other tracing implementations we
	// allow "true" and "false" as inputs for interop purposes.
	switch strings.ToLower(sampled) {
	case "0", "false":
		// Zero value for TraceFlags sample bit is unset.
	case "1", "true":
		prop.TraceFlags = FlagsSampled
	case "":
		ctx = withDeferred(ctx, true)
	default:
		return ctx, empty, errInvalidSampledHeader
	}

	// The only accepted value for Flags is "1". This will set Debug bitmask and
	// sampled bitmask to 1 since debug implicitly means sampled. All other
	// values and omission of header will be ignored. According to the spec. User
	// shouldn't send X-B3-Sampled header along with X-B3-Flags header. Thus we will
	// ignore X-B3-Sampled header when X-B3-Flags header is sent and valid.
	if flags == "1" {
		ctx = withDeferred(ctx, false)
		ctx = withDebug(ctx, true)
		prop.TraceFlags |= FlagsSampled
	}

	if traceID != "" {
		requiredCount++
		id := traceID
		if len(traceID) == 16 {
			// Pad 64-bit trace IDs.
			id = b3TraceIDPadding + traceID
		}
		tID, err := traceIDFromHex(id)
		if err != nil {
			return ctx, empty, errInvalidTraceIDHeader
		}
		prop.TraceID = tID.String()
	}

	if spanID != "" {
		requiredCount++
		sID, err := spanIDFromHex(spanID)
		if err != nil {
			return ctx, empty, errInvalidSpanIDHeader
		}
		prop.ParentID = sID.String()
	}

	if requiredCount != 0 && requiredCount != 2 {
		return ctx, empty, errInvalidScope
	}

	if parentSpanID != "" {
		if requiredCount == 0 {
			return ctx, empty, errInvalidScopeParent
		}
		// Validate parent span ID but we do not use it so do not save it.
		if _, err = spanIDFromHex(parentSpanID); err != nil {
			return ctx, empty, errInvalidParentSpanIDHeader
		}
	}

	return ctx, prop, nil
}

// extractSingle reconstructs a SpanContext from contextHeader based on a B3
// Single header. It is based on the implementation found here:
// https://github.com/openzipkin/zipkin-go/blob/v0.2.2/propagation/b3/spancontext.go
// and adapted to support a SpanContext.
func extractSingle(ctx context.Context, contextHeader string) (context.Context, PropagationContext, error) {
	if contextHeader == "" {
		return ctx, empty, errEmptyContext
	}

	var (
		prop     = PropagationContext{}
		sampling string
	)

	headerLen := len(contextHeader)

	if headerLen == samplingWidth {
		sampling = contextHeader
	} else if headerLen == traceID64BitsWidth || headerLen == traceID128BitsWidth {
		// Trace ID by itself is invalid.
		return ctx, empty, errInvalidScope
	} else if headerLen >= traceID64BitsWidth+spanIDWidth+separatorWidth {
		pos := 0
		var traceID string
		if string(contextHeader[traceID64BitsWidth]) == "-" {
			// traceID must be 64 bits
			pos += traceID64BitsWidth // {traceID}
			traceID = b3TraceIDPadding + string(contextHeader[0:pos])
		} else if string(contextHeader[32]) == "-" {
			// traceID must be 128 bits
			pos += traceID128BitsWidth // {traceID}
			traceID = string(contextHeader[0:pos])
		} else {
			return ctx, empty, errInvalidTraceIDValue
		}
		var err error
		tID, err := traceIDFromHex(traceID)
		if err != nil {
			return ctx, empty, errInvalidTraceIDValue
		}
		prop.TraceID = tID.String()

		pos += separatorWidth // {traceID}-

		spanID, err := spanIDFromHex(contextHeader[pos : pos+spanIDWidth])
		if err != nil {
			return ctx, empty, errInvalidSpanIDValue
		}
		prop.ParentID = spanID.String()
		pos += spanIDWidth // {traceID}-{spanID}

		if headerLen > pos {
			if headerLen == pos+separatorWidth {
				// {traceID}-{spanID}- is invalid.
				return ctx, empty, errInvalidSampledByte
			}
			pos += separatorWidth // {traceID}-{spanID}-

			if headerLen == pos+samplingWidth {
				sampling = string(contextHeader[pos])
			} else if headerLen == pos+parentSpanIDWidth {
				// {traceID}-{spanID}-{parentSpanID} is invalid.
				return ctx, empty, errInvalidScopeParentSingle
			} else if headerLen == pos+samplingWidth+separatorWidth+parentSpanIDWidth {
				sampling = string(contextHeader[pos])
				pos += samplingWidth + separatorWidth // {traceID}-{spanID}-{sampling}-

				// Validate parent span ID but we do not use it so do not
				// save it.
				_, err = spanIDFromHex(contextHeader[pos:])
				if err != nil {
					return ctx, empty, errInvalidParentSpanIDValue
				}
			} else {
				return ctx, empty, errInvalidParentSpanIDValue
			}
		}
	} else {
		return ctx, empty, errInvalidTraceIDValue
	}
	switch sampling {
	case "":
		ctx = withDeferred(ctx, true)
	case "d":
		ctx = withDebug(ctx, true)
		prop.TraceFlags = FlagsSampled
	case "1":
		prop.TraceFlags = FlagsSampled
	case "0":
		// Zero value for TraceFlags sample bit is unset.
	default:
		return ctx, empty, errInvalidSampledByte
	}

	return ctx, prop, nil
}

type b3KeyType int

const (
	debugKey b3KeyType = iota
	deferredKey
)

// withDebug returns a copy of parent with debug set as the debug flag value .
func withDebug(parent context.Context, debug bool) context.Context {
	return context.WithValue(parent, debugKey, debug)
}

// deferredFromContext returns the deferred value stored in ctx.
//
// If no deferred value is stored in ctx false is returned.
func deferredFromContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	if deferred, ok := ctx.Value(deferredKey).(bool); ok {
		return deferred
	}
	return false
}

// withDeferred returns a copy of parent with deferred set as the deferred flag value .
func withDeferred(parent context.Context, deferred bool) context.Context {
	return context.WithValue(parent, deferredKey, deferred)
}

// debugFromContext returns the debug value stored in ctx.
//
// If no debug value is stored in ctx false is returned.
func debugFromContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	if debug, ok := ctx.Value(debugKey).(bool); ok {
		return debug
	}
	return false
}

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

	if prop.TraceID == "" {
		return ctx, headerMap
	}

	if len(prop.TraceID) != 32 {
		// not a valid trace id
		return ctx, headerMap
	}

	headerMap[b3TraceIDHeader] = prop.TraceID
	headerMap[b3SpanIDHeader] = prop.ParentID

	if debugFromContext(ctx) {
		headerMap[b3DebugFlagHeader] = "1"
	} else if !(deferredFromContext(ctx)) {
		if prop.TraceFlags.IsSampled() {
			headerMap[b3SampledHeader] = "1"
		} else {
			headerMap[b3SampledHeader] = "0"
		}
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
	prop := PropagationContext{}
	var err error
	if h := getHeaderValue(headers, b3ContextHeader); h != "" {
		ctx, prop, err = extractSingle(ctx, h)
		if err == nil {
			return ctx, &prop, err
		}
	}
	var (
		traceID      = getHeaderValue(headers, b3TraceIDHeader)
		spanID       = getHeaderValue(headers, b3SpanIDHeader)
		parentSpanID = getHeaderValue(headers, b3ParentSpanIDHeader)
		sampled      = getHeaderValue(headers, b3SampledHeader)
		debugFlag    = getHeaderValue(headers, b3DebugFlagHeader)
	)
	ctx, prop, _ = extractMultiple(ctx, traceID, spanID, parentSpanID, sampled, debugFlag)
	if !prop.IsValid() {
		return ctx, nil, errors.New("cannot unmarshal empty header")
	}
	return ctx, &prop, nil
}
