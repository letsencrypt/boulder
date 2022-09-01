package propagation

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
)

const (
	supportedVersion  = 0
	maxVersion        = 254
	TraceparentHeader = "traceparent"
	tracestateHeader  = "tracestate"
)

var traceCtxRegExp = regexp.MustCompile("^(?P<version>[0-9a-f]{2})-(?P<traceID>[a-f0-9]{32})-(?P<spanID>[a-f0-9]{16})-(?P<traceFlags>[a-f0-9]{2})(?:-.*)?$")

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

	traceID, err := traceIDFromHex(prop.TraceID)
	if err != nil {
		return ctx, headerMap
	}
	spanID, err := spanIDFromHex(prop.ParentID)
	if err != nil {
		return ctx, headerMap
	}

	headerMap[tracestateHeader] = prop.TraceState.String()

	// Clear all flags other than the trace-context supported sampling bit.
	flags := prop.TraceFlags & FlagsSampled

	h := fmt.Sprintf("%.2x-%s-%s-%s",
		supportedVersion,
		traceID,
		spanID,
		flags)

	headerMap[TraceparentHeader] = h
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
	prop := &PropagationContext{}

	h := getHeaderValue(headers, TraceparentHeader)
	if h == "" {
		return ctx, prop, errors.New("cannot unmarshal empty header")
	}

	matches := traceCtxRegExp.FindStringSubmatch(h)

	if len(matches) == 0 {
		return ctx, prop, errors.New("invalid header format")
	}

	if len(matches) < 5 { // four subgroups plus the overall match
		return ctx, prop, errors.New("invalid header")
	}

	if len(matches[1]) != 2 {
		return ctx, prop, errors.New("invalid header. could not parse")
	}
	ver, err := hex.DecodeString(matches[1])
	if err != nil {
		return ctx, prop, errors.New("could not decode version")
	}
	version := int(ver[0])
	if version > maxVersion {
		return ctx, prop, errors.New("unsupported version")
	}

	if version == 0 && len(matches) != 5 { // four subgroups plus the overall match
		return ctx, prop, errors.New("incorrect number of subgroups in header")
	}

	if len(matches[2]) != 32 {
		return ctx, prop, errors.New("invalid trace id format")
	}

	traceID, err := traceIDFromHex(matches[2][:32])
	if err != nil {
		return ctx, prop, errors.New("unable to parse trace id")
	}

	prop.TraceID = traceID.String()

	if len(matches[3]) != 16 {
		return ctx, prop, errors.New("invalid span id format")
	}

	spanID, err := spanIDFromHex(matches[3])
	if err != nil {
		return ctx, prop, errors.New("unable to parse span id")
	}

	prop.ParentID = spanID.String()

	if len(matches[4]) != 2 {
		return ctx, prop, errors.New("invalid traceflags format")
	}
	opts, err := hex.DecodeString(matches[4])
	if err != nil || len(opts) < 1 || (version == 0 && opts[0] > 2) {
		return ctx, prop, errors.New("unable to parse traceflags")
	}
	// Clear all flags other than the trace-context supported sampling bit.
	prop.TraceFlags = TraceFlags(opts[0]) & FlagsSampled

	// Ignore the error returned here. Failure to parse tracestate MUST NOT
	// affect the parsing of traceparent according to the W3C tracecontext
	// specification.
	prop.TraceState, _ = ParseTraceState(getHeaderValue(headers, tracestateHeader))

	return ctx, prop, nil
}
