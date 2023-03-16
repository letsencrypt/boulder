// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package filters // import "go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc/filters"

import (
	"path"
	"strings"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
)

type gRPCPath struct {
	service string
	method  string
}

// splitFullMethod splits path defined in gRPC protocol
// and returns as gRPCPath object that has divided service and method names
// https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md
// If name is not FullMethod, returned gRPCPath has empty service field.
func splitFullMethod(i *otelgrpc.InterceptorInfo) gRPCPath {
	var name string
	switch i.Type {
	case otelgrpc.UnaryServer:
		name = i.UnaryServerInfo.FullMethod
	case otelgrpc.StreamServer:
		name = i.StreamServerInfo.FullMethod
	case otelgrpc.UnaryClient, otelgrpc.StreamClient:
		name = i.Method
	default:
		name = i.Method
	}

	s, m := path.Split(name)
	if s != "" {
		s = path.Clean(s)
		s = strings.TrimLeft(s, "/")
	}

	return gRPCPath{
		service: s,
		method:  m,
	}
}

// Any takes a list of Filters and returns a Filter that
// returns true if any Filter in the list returns true.
func Any(fs ...otelgrpc.Filter) otelgrpc.Filter {
	return func(i *otelgrpc.InterceptorInfo) bool {
		for _, f := range fs {
			if f(i) {
				return true
			}
		}
		return false
	}
}

// All takes a list of Filters and returns a Filter that
// returns true only if all Filters in the list return true.
func All(fs ...otelgrpc.Filter) otelgrpc.Filter {
	return func(i *otelgrpc.InterceptorInfo) bool {
		for _, f := range fs {
			if !f(i) {
				return false
			}
		}
		return true
	}
}

// None takes a list of Filters and returns a Filter that returns
// true only if none of the Filters in the list return true.
func None(fs ...otelgrpc.Filter) otelgrpc.Filter {
	return Not(Any(fs...))
}

// Not provides a convenience mechanism for inverting a Filter.
func Not(f otelgrpc.Filter) otelgrpc.Filter {
	return func(i *otelgrpc.InterceptorInfo) bool {
		return !f(i)
	}
}

// MethodName returns a Filter that returns true if the request's
// method name matches the provided string n.
func MethodName(n string) otelgrpc.Filter {
	return func(i *otelgrpc.InterceptorInfo) bool {
		p := splitFullMethod(i)
		return p.method == n
	}
}

// MethodPrefix returns a Filter that returns true if the request's
// method starts with the provided string pre.
func MethodPrefix(pre string) otelgrpc.Filter {
	return func(i *otelgrpc.InterceptorInfo) bool {
		p := splitFullMethod(i)
		return strings.HasPrefix(p.method, pre)
	}
}

// FullMethodName returns a Filter that returns true if the request's
// full RPC method string, i.e. /package.service/method, starts with
// the provided string n.
func FullMethodName(n string) otelgrpc.Filter {
	return func(i *otelgrpc.InterceptorInfo) bool {
		var fm string
		switch i.Type {
		case otelgrpc.UnaryClient, otelgrpc.StreamClient:
			fm = i.Method
		case otelgrpc.UnaryServer:
			fm = i.UnaryServerInfo.FullMethod
		case otelgrpc.StreamServer:
			fm = i.StreamServerInfo.FullMethod
		default:
			fm = i.Method
		}
		return fm == n
	}
}

// ServiceName returns a Filter that returns true if the request's
// service name, i.e. package.service, matches s.
func ServiceName(s string) otelgrpc.Filter {
	return func(i *otelgrpc.InterceptorInfo) bool {
		p := splitFullMethod(i)
		return p.service == s
	}
}

// ServicePrefix returns a Filter that returns true if the request's
// service name, i.e. package.service, starts with the provided string pre.
func ServicePrefix(pre string) otelgrpc.Filter {
	return func(i *otelgrpc.InterceptorInfo) bool {
		p := splitFullMethod(i)
		return strings.HasPrefix(p.service, pre)
	}
}

// HealthCheck returns a Filter that returns true if the request's
// service name is health check defined by gRPC Health Checking Protocol.
// https://github.com/grpc/grpc/blob/master/doc/health-checking.md
func HealthCheck() otelgrpc.Filter {
	return ServicePrefix("grpc.health.v1.Health")
}
