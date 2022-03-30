package propagation

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
)

// this file contains definitions of types used in propagation between OpenTelemetry and
// beeline instrumented applications. Many of the types have been lifted from the
// opentelemetry-go sdk found here:
// https://github.com/open-telemetry/opentelemetry-go/blob/c912b179fd595cc7c6eec0b22e6c1371e31241d7/trace/trace.go

const (
	// FlagsSampled is a bitmask with the sampled bit set. A SpanContext
	// with the sampling bit set means the span is sampled.
	FlagsSampled = TraceFlags(0x01)

	errInvalidHexID errorConst = "trace-id and span-id can only contain [0-9a-f] characters, all lowercase"

	errInvalidTraceIDLength errorConst = "hex encoded trace-id must have length equals to 32"
	errNilTraceID           errorConst = "trace-id can't be all zero"

	errInvalidSpanIDLength errorConst = "hex encoded span-id must have length equals to 16"
	errNilSpanID           errorConst = "span-id can't be all zero"
)

type errorConst string

func (e errorConst) Error() string {
	return string(e)
}

// traceID is a unique identity of a trace.
type traceID [16]byte

var nilTraceID traceID
var _ json.Marshaler = nilTraceID

// IsValid checks whether the trace traceID is valid. A valid trace ID does
// not consist of zeros only.
func (t traceID) IsValid() bool {
	return !bytes.Equal(t[:], nilTraceID[:])
}

// MarshalJSON implements a custom marshal function to encode traceID
// as a hex string.
func (t traceID) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// String returns the hex string representation form of a traceID
func (t traceID) String() string {
	return hex.EncodeToString(t[:])
}

// spanID is a unique identity of a span in a trace.
type spanID [8]byte

var nilSpanID spanID
var _ json.Marshaler = nilSpanID

// IsValid checks whether the spanID is valid. A valid spanID does not consist
// of zeros only.
func (s spanID) IsValid() bool {
	return !bytes.Equal(s[:], nilSpanID[:])
}

// MarshalJSON implements a custom marshal function to encode spanID
// as a hex string.
func (s spanID) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// String returns the hex string representation form of a SsanID
func (s spanID) String() string {
	return hex.EncodeToString(s[:])
}

// TraceIDFromHex returns a traceID from a hex string if it is compliant with
// the W3C trace-context specification.  See more at
// https://www.w3.org/TR/trace-context/#trace-id
// nolint:revive // revive complains about stutter of `trace.TraceIDFromHex`.
func traceIDFromHex(h string) (traceID, error) {
	t := traceID{}
	if len(h) != 32 {
		return t, errInvalidTraceIDLength
	}

	if err := decodeHex(h, t[:]); err != nil {
		return t, err
	}

	if !t.IsValid() {
		return t, errNilTraceID
	}
	return t, nil
}

// SpanIDFromHex returns a spanID from a hex string if it is compliant
// with the w3c trace-context specification.
// See more at https://www.w3.org/TR/trace-context/#parent-id
func spanIDFromHex(h string) (spanID, error) {
	s := spanID{}
	if len(h) != 16 {
		return s, errInvalidSpanIDLength
	}

	if err := decodeHex(h, s[:]); err != nil {
		return s, err
	}

	if !s.IsValid() {
		return s, errNilSpanID
	}
	return s, nil
}

func decodeHex(h string, b []byte) error {
	for _, r := range h {
		switch {
		case 'a' <= r && r <= 'f':
			continue
		case '0' <= r && r <= '9':
			continue
		default:
			return errInvalidHexID
		}
	}

	decoded, err := hex.DecodeString(h)
	if err != nil {
		return err
	}

	copy(b, decoded)
	return nil
}

// TraceFlags contains flags that can be set on a SpanContext
type TraceFlags byte //nolint:revive // revive complains about stutter of `trace.TraceFlags`.

// IsSampled returns if the sampling bit is set in the TraceFlags.
func (tf TraceFlags) IsSampled() bool {
	return tf&FlagsSampled == FlagsSampled
}

// WithSampled sets the sampling bit in a new copy of the TraceFlags.
func (tf TraceFlags) WithSampled(sampled bool) TraceFlags {
	if sampled {
		return tf | FlagsSampled
	}

	return tf &^ FlagsSampled
}

// MarshalJSON implements a custom marshal function to encode TraceFlags
// as a hex string.
func (tf TraceFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(tf.String())
}

// String returns the hex string representation form of TraceFlags
func (tf TraceFlags) String() string {
	return hex.EncodeToString([]byte{byte(tf)}[:])
}
