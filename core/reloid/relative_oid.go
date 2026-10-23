package reloid

import (
	"bytes"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// RelativeOID represents an ASN.1 Relative OID. This is similar to the Go
// stdlib's x509.OID and ans1.OID, except that it does not perform the
// first-two-components packing optimization that non-relative OIDs use. It also
// limits each OID component to fit in a uint32, a restriction which does not
// exist in the ASN.1 spec but seems nonetheless reasonable.
type RelativeOID struct {
	der []byte
	str string
}

// FromString parses a Relative OID from its dotted-decimal string representation.
// It rejects any input which is empty, has empty components (two dots in a row),
// has non-canonical components (leading zeros or plus signs), has negative
// components, or has components too large to fit in an int32.
func FromString(in string) (*RelativeOID, error) {
	strs := strings.Split(in, ".")
	var ints []uint32
	for _, s := range strs {
		comp64, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid relative oid component %q: %w", s, err)
		}
		if strconv.FormatUint(comp64, 10) != s {
			return nil, fmt.Errorf("relative oid component %q is not in canonical form", s)
		}
		ints = append(ints, uint32(comp64))
	}
	return fromInts(ints)
}

// FromBytes parses a Relative OID from its DER representation, not including
// the leading tag and length bytes. It rejects any input which is empty, has
// incorrectly-encoded components, or has components too large to fit in an int32.
func FromBytes(in []byte) (*RelativeOID, error) {
	var ints []uint32
	i := 0
	for i < len(in) {
		c, used, err := decodeRelativeOIDComponent(in[i:])
		if err != nil {
			return nil, err
		}
		ints = append(ints, c)
		i += used
	}
	return fromInts(ints)
}

// decodeRelativeOIDComponent parses the head of `in` as a single OID component.
// It returns the parsed integer and the number of bytes of input consumed. It
// returns an error if the leading bytes don't represent an OID-encoded int.
func decodeRelativeOIDComponent(in []byte) (uint32, int, error) {
	var comp64 uint64
	for i, b := range in {
		if i == 0 && b == 0x80 {
			// The first byte of a component should never be 0x80 (a leading 0).
			return 0, 0, fmt.Errorf("OID component not minimally encoded")
		}

		if i >= 5 {
			// Each byte represents 7 bits of the resulting int. If we've made it to
			// a byte at index 5, we've already processed 5 * 7 = 35 bits, which is
			// too many to fit in a 32-bit int.
			return 0, 0, fmt.Errorf("OID component too large")
		}

		// Shift any previous bytes and append the new one.
		comp64 <<= 7
		comp64 |= uint64(b & 0x7f)

		// If the leading bit is zero, this was the last byte of the component.
		if b&0x80 == 0 {
			if comp64 > math.MaxUint32 {
				return 0, 0, fmt.Errorf("OID component too large")
			}
			return uint32(comp64), i + 1, nil
		}
	}
	return 0, 0, fmt.Errorf("OID component truncated")
}

// fromInts is a helper constructor which first checks that the input is a valid
// relative OID, then encodes it to both a string and DER bytes for easy access
// later. It's easiest to perform those checks on integers, not strings or
// bytes, hence the input type.
func fromInts(components []uint32) (*RelativeOID, error) {
	if len(components) == 0 {
		return nil, fmt.Errorf("empty relative OID")
	}

	var der []byte
	var strs []string
	for _, c := range components {
		strs = append(strs, strconv.FormatUint(uint64(c), 10))

		// Count the number of bytes necessary to hold the component's bits, given
		// that each byte only encodes 7 bits.
		var l int64
		if c == 0 {
			l = 1
		} else {
			for i := c; i > 0; i >>= 7 {
				l++
			}
		}

		// Encode the component starting from its most significant bits, setting
		// the most significant bit of each byte to 1, unless it is the last byte.
		for i := l - 1; i >= 0; i-- {
			o := byte((c >> uint(i*7)) & 0x7f)
			if i != 0 {
				o |= 0x80
			}

			der = append(der, o)
		}
	}

	return &RelativeOID{
		der: der,
		str: strings.Join(strs, "."),
	}, nil
}

// String returns the dotted-decimal string representation of the relative OID.
// It is the inverse of FromString.
func (r *RelativeOID) String() string {
	return r.str
}

// Bytes returns the DER-encoded byte representation of the relative OID, not
// including the tag and length bytes. It is the inverse of FromBytes.
func (r *RelativeOID) Bytes() []byte {
	return bytes.Clone(r.der)
}
