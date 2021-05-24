package propagation

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// assumes a header of the form:

// VERSION;PAYLOAD

// VERSION=1
// =========
// PAYLOAD is a list of comma-separated params (k=v pairs), with no spaces.  recognized
// keys + value types:
//
//  trace_id=${traceId}    - traceId is an opaque ascii string which shall not include ','
//  parent_id=${spanId}    - spanId is an opaque ascii string which shall not include ','
//  dataset=${datasetId}   - datasetId is the slug for the honeycomb dataset to which downstream spans should be sent; shall not include ','
//  context=${contextBlob} - contextBlob is a base64 encoded json object.
//
// ex: X-Honeycomb-Trace: 1;trace_id=weofijwoeifj,parent_id=owefjoweifj,context=eyJoZWxsbyI6IndvcmxkIn0=

const (
	TracePropagationGRPCHeader = "x-honeycomb-trace" // difference in case matters here
	TracePropagationHTTPHeader = "X-Honeycomb-Trace"
	TracePropagationVersion    = 1
)

// MarshalHoneycombTraceContext uses the information in prop to create a trace context header
// in the Honeycomb trace header format. It returns the serialized form of the trace context,
// ready to be inserted into the headers of an outbound HTTP request.
//
// If prop is nil, the returned value will be an empty string.
func MarshalHoneycombTraceContext(prop *PropagationContext) string {
	if prop == nil {
		return ""
	}
	tcJSON, err := json.Marshal(prop.TraceContext)
	if err != nil {
		// if we couldn't marshal the trace level fields, leave it blank
		tcJSON = []byte("")
	}

	tcB64 := base64.StdEncoding.EncodeToString(tcJSON)

	var datasetClause string
	if prop.Dataset != "" {
		datasetClause = fmt.Sprintf("dataset=%s,", url.QueryEscape(prop.Dataset))
	}

	return fmt.Sprintf(
		"%d;trace_id=%s,parent_id=%s,%scontext=%s",
		TracePropagationVersion,
		prop.TraceID,
		prop.ParentID,
		datasetClause,
		tcB64,
	)
}

// UnmarshalHoneycombTraceContext parses the information provided in header and creates a
// PropagationContext instance.
//
// If the header cannot be used to construct a PropagationContext with a trace id and parent id,
// an error will be returned.
func UnmarshalHoneycombTraceContext(header string) (*PropagationContext, error) {
	// pull the version out of the header
	getVer := strings.SplitN(header, ";", 2)
	if getVer[0] == "1" {
		return unmarshalHoneycombTraceContextV1(getVer[1])
	}
	return nil, &PropagationError{fmt.Sprintf("unrecognized version for trace header %s", getVer[0]), nil}
}

// unmarshalHoneycombTraceContextV1 takes the trace header, stripped of the
// version string, and returns the component parts. If the header includes a
// parent id but not a trace id, or if the header contains an unparseable
// string in the trace context, an error will be returned.
func unmarshalHoneycombTraceContextV1(header string) (*PropagationContext, error) {
	clauses := strings.Split(header, ",")
	var prop = &PropagationContext{}
	var tcB64 string
	for _, clause := range clauses {
		keyval := strings.SplitN(clause, "=", 2)
		switch keyval[0] {
		case "trace_id":
			prop.TraceID = keyval[1]
		case "parent_id":
			prop.ParentID = keyval[1]
		case "dataset":
			prop.Dataset, _ = url.QueryUnescape(keyval[1])
		case "context":
			tcB64 = keyval[1]
		}
	}
	if prop.TraceID == "" && prop.ParentID != "" {
		return nil, &PropagationError{"parent_id without trace_id", nil}
	}
	if tcB64 != "" {
		data, err := base64.StdEncoding.DecodeString(tcB64)
		if err != nil {
			return nil, &PropagationError{"unable to decode base64 trace context", err}
		}
		prop.TraceContext = make(map[string]interface{})
		err = json.Unmarshal(data, &prop.TraceContext)
		if err != nil {
			return nil, &PropagationError{"unable to unmarshal trace context", err}
		}
	}
	return prop, nil
}
