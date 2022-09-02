package hnygrpc

import (
	"context"
	"net"
	"reflect"
	"runtime"

	"github.com/honeycombio/beeline-go/propagation"
	"github.com/honeycombio/beeline-go/timer"
	"github.com/honeycombio/beeline-go/trace"
	"github.com/honeycombio/beeline-go/wrappers/config"
	"github.com/honeycombio/libhoney-go"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// This is a map of GRPC request header names whose values will be retrieved
// and added to handler spans as fields with the corresponding name.
//
// Header names must be lowercase as the metadata.MD API will have normalized
// incoming headers to lower.
//
// The field names should turn dashes (-) into underscores (_) to follow
// precident in HTTP request headers and the patterns established and in
// naming patterns in OTel attributes for requests.
var headersToFields = map[string]string{
	"content-type":      "request.content_type",
	":authority":        "request.header.authority",
	"user-agent":        "request.header.user_agent",
	"x-forwarded-for":   "request.header.x_forwarded_for",
	"x-forwarded-proto": "request.header.x_forwarded_proto",
}

// getMetadataStringValue is a simpler helper method that checks the provided
// metadata for a value associated with the provided key. If the value exists,
// it is returned. If the value does not exist, an empty string is returned.
func getMetadataStringValue(md metadata.MD, key string) string {
	if val, ok := md[key]; ok {
		if len(val) > 0 {
			return val[0]
		}
		return ""
	}
	return ""
}

// startSpanOrTraceFromUnaryGRPC checks to see if a trace already exists in the
// provided context before creating either a root span or a child span of the
// existing active span. The function understands trace parser hooks, so if one
// is provided, it'll use it to parse the incoming request for trace context.
func startSpanOrTraceFromUnaryGRPC(
	ctx context.Context,
	info *grpc.UnaryServerInfo,
	parserHook config.GRPCTraceParserHook,
) (context.Context, *trace.Span) {
	span := trace.GetSpanFromContext(ctx)
	if span == nil {
		// no active span, create a new trace
		var tr *trace.Trace
		md, ok := metadata.FromIncomingContext(ctx)
		if ok {
			if parserHook == nil {
				beelineHeader := getMetadataStringValue(md, propagation.TracePropagationGRPCHeader)
				prop, _ := propagation.UnmarshalHoneycombTraceContext(beelineHeader)
				ctx, tr = trace.NewTrace(ctx, prop)
			} else {
				prop := parserHook(ctx)
				ctx, tr = trace.NewTraceFromPropagationContext(ctx, prop)
			}
		} else {
			ctx, tr = trace.NewTrace(ctx, nil)
		}
		span = tr.GetRootSpan()
	} else {
		// create new span as child of active span.
		ctx, span = span.CreateChild(ctx)
	}
	return ctx, span
}

// addFields just adds available information about a gRPC request to the provided span.
func addFields(ctx context.Context, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler, span *trace.Span) {
	handlerName := runtime.FuncForPC(reflect.ValueOf(handler).Pointer()).Name()

	span.AddField("name", handlerName)
	span.AddField("meta.type", "grpc_request")
	span.AddField("handler.name", handlerName)
	span.AddField("handler.method", info.FullMethod)

	pr, ok := peer.FromContext(ctx)
	if ok {
		// if we have an address, put it on the span
		if pr.Addr != net.Addr(nil) {
			span.AddField("request.remote_addr", pr.Addr.String())
		}
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		for headerName, fieldName := range headersToFields {
			if val, ok := md[headerName]; ok {
				span.AddField(fieldName, val[0])
			}
		}
	}
}

// UnaryServerInterceptorWithConfig will create a Honeycomb event per invocation of the
// returned interceptor. If passed a config.GRPCIncomingConfig with a GRPCParserHook,
// the hook will be called when creating the event, allowing it to specify how trace context
// information should be included in the span (e.g. it may have come from a remote parent in
// a specific format).
//
// Events created from GRPC interceptors will contain information from the gRPC metadata, if
// it exists, as well as information about the handler used and method being called.
func UnaryServerInterceptorWithConfig(cfg config.GRPCIncomingConfig) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		ctx, span := startSpanOrTraceFromUnaryGRPC(ctx, info, cfg.GRPCParserHook)
		defer span.Send()

		addFields(ctx, info, handler, span)
		resp, err := handler(ctx, req)
		if err != nil {
			span.AddTraceField("handler_error", err.Error())
		}
		code := status.Code(err)
		span.AddField("response.grpc_status_code", code)
		span.AddField("response.grpc_status_message", code.String())
		return resp, err
	}
}

// UnaryServerInterceptor is identical to UnaryServerInterceptorWithConfig called
// with an empty config.GRPCIncomingConfig.
func UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return UnaryServerInterceptorWithConfig(config.GRPCIncomingConfig{})
}

// UnaryClientInterceptorWithConfig will create a Honeycomb span per invocation
// of the returned interceptor. It will also serialize the trace propagation
// context into the gRPC metadata so it can be deserialized by the server. If
// passed a config.GRPCOutgoingConfig with a GRPCTracePropagationHook, the hook
// will be called when populating the gRPC metadata, allowing it to specify how
// trace context information should be included in the metadata (e.g. if the
// remote server expects it to come in a specific format).
func UnaryClientInterceptorWithConfig(cfg config.GRPCOutgoingConfig) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req interface{},
		reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		span := trace.GetSpanFromContext(ctx)

		// If there's no active trace or span, just send an event.
		if span == nil {
			tm := timer.Start()
			ev := libhoney.NewEvent()
			defer ev.Send()

			ev.AddField("name", method)
			ev.AddField("meta.type", "grpc_client")
			ev.AddField("request.target", cc.Target())

			err := invoker(ctx, method, req, reply, cc, opts...)
			if err != nil {
				ev.AddField("error", err.Error())
			}
			dur := tm.Finish()
			ev.AddField("duration_ms", dur)
			return err
		}

		ctx, span = span.CreateChild(ctx)
		defer span.Send()

		span.AddField("name", method)
		span.AddField("meta.type", "grpc_client")
		span.AddField("request.target", cc.Target())

		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			md = metadata.New(nil)
		} else {
			// Modifying the result of FromOutgoingContext may race, so copy instead.
			md = md.Copy()
		}

		if cfg.GRPCPropagationHook == nil {
			md.Set(propagation.TracePropagationGRPCHeader, span.SerializeHeaders())
		} else {
			// If a propagationHook exists, call it to get a metadata to append.
			md = metadata.Join(md, cfg.GRPCPropagationHook(span.PropagationContext()))
		}

		ctx = metadata.NewOutgoingContext(ctx, md)
		err := invoker(ctx, method, req, reply, cc, opts...)
		if err != nil {
			span.AddField("error", err.Error())
		}
		return err
	}
}

// UnaryClientInterceptor is identical to UnaryClientInterceptorWithConfig called
// with an empty config.GRPCOutgoingConfig.
func UnaryClientInterceptor() grpc.UnaryClientInterceptor {
	return UnaryClientInterceptorWithConfig(config.GRPCOutgoingConfig{})
}
