// Package hnygrpc provides wrappers and other utilities for autoinstrumenting
// gRPC services.
//
// Usage
//
// The Honeycomb beeline takes advantage of gRPC interceptors to instrument
// RPCs. The wrapped interceptor can take a `config.GRPCIncomingConfig` object
// which can optionally provide a custom trace parser hook, allowing for easy
// interoperability between W3C, B3, Honeycomb and other trace header formats.
//
//     serverOpts := []grpc.ServerOption{
//         grpc.UnaryInterceptor(hnygrpc.UnaryServerInterceptorWithConfig(cfg)),
//     }
//     server := grpc.NewServer(serverOpts...)
//
// Requests received by the server will now generate Honeycomb events, with
// metadata related to the request included as fields.
//
// Please note that only unary RPCs are supported at this time. Support for
// streaming RPCs may be added later.
package hnygrpc
