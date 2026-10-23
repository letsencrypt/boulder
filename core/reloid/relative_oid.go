package reloid

import (
	"bytes"
	"fmt"
	"math"
	"strconv"
	"strings"
)

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
	var ints []int
	for _, s := range strs {
		c, err := strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf("invalid relative oid component %q: %w", s, err)
		}
		if strconv.Itoa(c) != s {
			return nil, fmt.Errorf("relative oid component %q is not in canonical form", s)
		}
		ints = append(ints, c)
	}
	return fromInts(ints...)
}

// FromBytes parses a Relative OID from its DER representation, not including
// the leading tag and length bytes. It rejects any input which is empty, has
// incorrectly-encoded components, or has components too large to fit in an int32.
func FromBytes(in []byte) (*RelativeOID, error) {
	var ints []int
	i := 0
	for i < len(in) {
		c, used, err := decodeRelativeOIDComponent(in[i:])
		if err != nil {
			return nil, err
		}
		ints = append(ints, c)
		i += used
	}
	return fromInts(ints...)
}

// decodeRelativeOIDComponent parses the head of in as a single OID component.
// It returns the parsed integer and the number of bytes of input consumed. It
// returns an error if the leading bytes don't represent an OID-encoded int.
func decodeRelativeOIDComponent(in []byte) (int, int, error) {
	var ret64 int64
	for i, b := range in {
		if i == 0 && b == 0x80 {
			// The leading octet of a component should never be 0x80.
			return 0, 0, fmt.Errorf("OID component not minimally encoded")
		}

		if i >= 5 {
			// Each byte is a 7-bit int. If we're decoding more than 5 bytes, that's
			// at least 7 * 5 = 35 bits, which is too big for an OID component (int32).
			return 0, 0, fmt.Errorf("OID component too large")
		}

		// Shift any previous bytes and append the new one.
		ret64 <<= 7
		ret64 |= int64(b & 0x7f)

		// If the leading bit is zero, this was the last byte of the component.
		if b&0x80 == 0 {
			if ret64 > math.MaxInt32 {
				return 0, 0, fmt.Errorf("OID component too large")
			}
			return int(ret64), i + 1, nil
		}
	}
	return 0, 0, fmt.Errorf("OID component truncated")
}

// fromInts is a helper constructor which first checks that the input is a valid
// relative OID, then encodes it to both a string and DER bytes for easy access
// later. It's easiest to perform those checks on integers, not strings or
// bytes, hence the input type.
func fromInts(components ...int) (*RelativeOID, error) {
	if len(components) == 0 {
		return nil, fmt.Errorf("empty relative OID")
	}

	var der []byte
	var strs []string
	for _, c := range components {
		if c < 0 {
			return nil, fmt.Errorf("relative OID component %d is negative", c)
		}

		if c > math.MaxInt32 {
			return nil, fmt.Errorf("relative OID component %d is too large", c)
		}

		strs = append(strs, strconv.Itoa(c))

		var l int64
		if c == 0 {
			l = 1
		} else {
			for i := c; i > 0; i >>= 7 {
				l++
			}
		}

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
