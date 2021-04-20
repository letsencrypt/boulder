// Package propagation includes types and functions for marshalling and unmarshalling trace
// context headers between various supported formats and an internal representation. It
// provides support for traces that cross process boundaries with support for interoperability
// between various kinds of trace context header formats.
package propagation

import (
	"fmt"

	"go.opentelemetry.io/otel/trace"
)

// PropagationContext contains information about a trace that can cross process boundaries.
// Typically this information is parsed from an incoming trace context header.
type PropagationContext struct {
	TraceID      string
	ParentID     string
	Dataset      string
	TraceContext map[string]interface{}
	TraceFlags   byte
	TraceState   trace.TraceState
}

// hasTraceID checks that the trace ID is valid.
func (prop PropagationContext) hasTraceID() bool {
	return prop.TraceID != "" && prop.TraceID != "00000000000000000000000000000000"
}

// hasParentID checks that the parent ID is valid.
func (prop PropagationContext) hasParentID() bool {
	return prop.ParentID != "" && prop.ParentID != "0000000000000000"
}

// IsValid checks if the PropagationContext is valid. A valid PropagationContext has a valid
// trace ID and parent ID.
func (prop PropagationContext) IsValid() bool {
	return prop.hasTraceID() && prop.hasParentID()
}

// PropagationError wraps any error encountered while parsing or serializing trace propagation
// contexts.
type PropagationError struct {
	message      string
	wrappedError error
}

// Error returns a formatted message containing the error.
func (p *PropagationError) Error() string {
	if p.wrappedError == nil {
		return p.message
	}
	return fmt.Sprintf(p.message, p.wrappedError)
}
