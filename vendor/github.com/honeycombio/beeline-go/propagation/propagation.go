// Package propagation includes types and functions for marshalling and unmarshalling trace
// context headers between various supported formats and an internal representation. It
// provides support for traces that cross process boundaries with support for interoperability
// between various kinds of trace context header formats.
package propagation

import (
	"fmt"
)

var GlobalConfig Config

type Config struct {
	PropagateDataset bool
}

// getHeaderValue is a helper function that is guaranteed to return a string. Given a key, it
// attempts to find the associated value in the provided header. If none is found, it returns
// an empty string.
func getHeaderValue(headers map[string]string, key string) string {
	if value, ok := headers[key]; ok {
		return value
	}
	return ""
}

// PropagationContext contains information about a trace that can cross process boundaries.
// Typically this information is parsed from an incoming trace context header.
type PropagationContext struct {
	TraceID      string
	ParentID     string
	Dataset      string
	TraceContext map[string]interface{}
	TraceFlags   TraceFlags
	TraceState   TraceState
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
