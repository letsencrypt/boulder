package propagation

import (
	"fmt"
	"strings"
)

// MarshalAmazonTraceContext uses the information in prop to create a trace context header
// in the Amazon AWS trace header format. It returns the serialized form of the trace
// context, ready to be inserted into the headers of an outbound HTTP request.
//
// If prop is nil, the returned value will be an empty string.
func MarshalAmazonTraceContext(prop *PropagationContext) string {
	if prop == nil {
		return ""
	}

	// From https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-request-tracing.html:
	// "If the X-Amzn-Trace-Id header is present and has a Self field, the load balancer updates
	// the value of the Self field."
	h := fmt.Sprintf("Root=%s;Parent=%s", prop.TraceID, prop.ParentID)

	if len(prop.TraceContext) != 0 {
		elems := make([]string, len(prop.TraceContext))
		i := 0
		for k, v := range prop.TraceContext {
			elems[i] = fmt.Sprintf("%s=%v", k, v)
			i++
		}
		traceContext := ";" + strings.Join(elems, ";")
		h = h + traceContext
	}

	return h
}

// UnmarshalAmazonTraceContext parses the information provided in the headers and creates
// a PropagationContext instance. The provided headers is expected to contain an X-Amzn-Trace-Id
// key which will contain the value of the Amazon header.
//
// According to the documentation for load balancer request tracing:
// https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-request-tracing.html
// An application can add arbitrary fields for its own purposes. The load balancer preserves these fields
// but does not use them. In our implementation, we stick these fields in the TraceContext field of the
// PropagationContext. We only support strings, so if the header contains foo=32,baz=true, both 32 and true
// will be put into the map as strings. Note that this differs from the Honeycomb header, where trace context
// fields are stored as a base64 encoded JSON object and unmarshaled into ints, bools, etc.
//
// If the header cannot be used to construct a valid PropagationContext, an error will be returned.
func UnmarshalAmazonTraceContext(header string) (*PropagationContext, error) {
	segments := strings.Split(header, ";")
	// From https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-request-tracing.html
	// If the X-Amzn-Trace-Id header is not present on an incoming request, the load balancer generates a header
	// with a Root field and forwards the request. If the X-Amzn-Trace-Id header is present and has a Root field,
	// the load balancer inserts a Self field, and forwards the request. If an application adds a header with a
	// Root field and a custom field, the load balancer preserves both fields, inserts a Self field, and forwards
	// the request. If the X-Amzn-Trace-Id header is present and has a Self field, the load balancer updates the
	// value of the self field.
	//
	// Using the documentation above (that applies to amazon load balancers) we look for self as the parent id
	// and root as the trace id.
	prop := &PropagationContext{}
	prop.TraceContext = make(map[string]interface{})
	var parent string
	for _, segment := range segments {
		keyval := strings.SplitN(segment, "=", 2)
		if len(keyval) < 2 {
			continue
		}
		switch strings.ToLower(keyval[0]) {
		case "self":
			prop.ParentID = keyval[1]
		case "root":
			prop.TraceID = keyval[1]
		case "parent":
			parent = keyval[1]
		default:
			prop.TraceContext[keyval[0]] = keyval[1]
		}
	}

	// Our primary use case is to support load balancers, so favor self over parent.
	// If, however, a parent is present and self is not, use it.
	if prop.ParentID == "" && parent != "" {
		prop.ParentID = parent
	}

	// If no header is provided to an ALB or ELB, it will generate a header
	// with a Root field and forwards the request. In this case it should be
	// used as both the parent id and the trace id.
	if prop.TraceID != "" && prop.ParentID == "" {
		prop.ParentID = prop.TraceID
	}

	if !prop.IsValid() {
		return nil, &PropagationError{fmt.Sprintf("unable to parse header into propagationcontext: %s", header), nil}
	}

	return prop, nil
}
