package config

import (
	"context"
	"net/http"

	"github.com/honeycombio/beeline-go/propagation"
	"google.golang.org/grpc/metadata"
)

// HTTPTraceParserHook is a function that will be invoked on all incoming HTTP requests
// when it is passed as a parameter to an http.Handler wrapper function such as the
// one provided in the hnynethttp package. It can be used to create a PropagationContext
// object using trace context propagation headers in the provided http.Request. It is
// expected that this hook will use one of the unmarshal functions exported in the
// propagation package for a number of supported formats (e.g. Honeycomb, AWS,
// W3C Trace Context, etc).
type HTTPTraceParserHook func(*http.Request) *propagation.PropagationContext

// HTTPTracePropagationHook is a function that will be invoked on all outgoing HTTP requests
// when it is passed as a parameter to a RoundTripper wrapper function such as the one
// provided in the hnynethttp package. It can be used to create a map of header names
// to header values that will be injected in the outgoing request. The information in
// the provided http.Request can be used to make decisions about what headers to include
// in the outgoing request, for example based on the hostname of the target of the request.
// The information in the provided PropagationContext should be used to create the serialized
// header values. It is expected that this hook will use one of the marshal functions exported
// in the propagation package for a number of supported formats (e.g. Honeycomb, AWS,
// W3C Trace Context, etc).
type HTTPTracePropagationHook func(*http.Request, *propagation.PropagationContext) map[string]string

// HTTPIncomingConfig stores configuration options relevant to HTTP requests that are handled by
// a wrapper.
type HTTPIncomingConfig struct {
	HTTPParserHook HTTPTraceParserHook
}

// HTTPOutgoingConfig stores configuration options relevant to HTTP requests being sent by an
// instrumented application.
type HTTPOutgoingConfig struct {
	HTTPPropagationHook HTTPTracePropagationHook
}

// GRPCTraceParserHook is a function that will be invoked on all incoming gRPC requests
// when it is passed as a parameter to an interceptor wrapper function such as the one
// provided in the hnygrpc package. It can be used to create a PropagationContext object
// using trace context propagation headers in the provided context. It is functionally
// identical to its HTTP counterpart, HTTPTraceParserHook.
type GRPCTraceParserHook func(context.Context) *propagation.PropagationContext

// GRPCTracePropagationHook is a function that will be invoked on all outgoing gRPC requests
// when it is passed as a parameter to a client interceptor wrapper function such as the one
// provided in the hnygrpc package. It can be used to create a gRPC metadata object
// that will be injected into the outgoing request. It is functionally identical
// to its HTTP counterpart, HTTPTracePropagationHook.
type GRPCTracePropagationHook func(*propagation.PropagationContext) metadata.MD

// GRPCIncomingConfig stores configuration options relevant to gRPC requests that are
// handled by a wrapped gRPC interceptor provided in the hnygrpc package.
type GRPCIncomingConfig struct {
	GRPCParserHook GRPCTraceParserHook
}

// GRPCOutgoingConfig stores configuration options relevant to gRPC requests being sent
// by an instrumented application.
type GRPCOutgoingConfig struct {
	GRPCPropagationHook GRPCTracePropagationHook
}
