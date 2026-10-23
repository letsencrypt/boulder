package reloid

import (
	"bytes"
	"testing"
)

func TestRelativeOID(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		oid     string
		encoded []byte
	}{
		{name: "zero", oid: "0", encoded: []byte{0x00}},
		{name: "largest one-byte component", oid: "127", encoded: []byte{0x7f}},
		{name: "smallest two-byte component", oid: "128", encoded: []byte{0x81, 0x00}},
		{name: "largest two-byte component", oid: "16383", encoded: []byte{0xff, 0x7f}},
		{name: "smallest three-byte component", oid: "16384", encoded: []byte{0x81, 0x80, 0x00}},
		{name: "largest three-byte component", oid: "2097151", encoded: []byte{0xff, 0xff, 0x7f}},
		{name: "smallest four-byte component", oid: "2097152", encoded: []byte{0x81, 0x80, 0x80, 0x00}},
		{name: "largest four-byte component", oid: "268435455", encoded: []byte{0xff, 0xff, 0xff, 0x7f}},
		{name: "smallest five-byte component", oid: "268435456", encoded: []byte{0x81, 0x80, 0x80, 0x80, 0x00}},
		{name: "multiple one-byte components", oid: "85.2", encoded: []byte{0x55, 0x02}},
		{name: "multiple zero components", oid: "0.0.0", encoded: []byte{0x00, 0x00, 0x00}},
		{name: "multi-byte last component", oid: "85.2.8192", encoded: []byte{0x55, 0x02, 0xc0, 0x00}},
		{name: "multi-byte first component", oid: "180.3", encoded: []byte{0x81, 0x34, 0x03}},
		{name: "private enterprise number", oid: "32473.9", encoded: []byte{0x81, 0xfd, 0x59, 0x09}},
		{name: "five-byte component", oid: "1492336001", encoded: []byte{0x85, 0xc7, 0xcc, 0xfb, 0x01}},
		{name: "max int32", oid: "2147483647", encoded: []byte{0x87, 0xff, 0xff, 0xff, 0x7f}},
		{
			name:    "multiple multi-byte components",
			oid:     "128.16384.2147483647",
			encoded: []byte{0x81, 0x00, 0x81, 0x80, 0x00, 0x87, 0xff, 0xff, 0xff, 0x7f},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fromString, err := FromString(tc.oid)
			if err != nil {
				t.Errorf("FromString(%q) = %s, want success", tc.oid, err)
			} else {
				if fromString.String() != tc.oid {
					t.Errorf("FromString(%q).String() = %q, want %q", tc.oid, fromString.String(), tc.oid)
				}
				if !bytes.Equal(fromString.Bytes(), tc.encoded) {
					t.Errorf("FromString(%q).Bytes() = %x, want %x", tc.oid, fromString.Bytes(), tc.encoded)
				}
			}

			fromBytes, err := FromBytes(tc.encoded)
			if err != nil {
				t.Errorf("FromBytes(%x) = %s, want success", tc.encoded, err)
			} else {
				if fromBytes.String() != tc.oid {
					t.Errorf("FromBytes(%x).String() = %q, want %q", tc.encoded, fromBytes.String(), tc.oid)
				}
				if !bytes.Equal(fromBytes.Bytes(), tc.encoded) {
					t.Errorf("FromBytes(%x).Bytes() = %x, want %x", tc.encoded, fromBytes.Bytes(), tc.encoded)
				}
			}
		})
	}
}

func TestFromStringInvalid(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		oid  string
	}{
		{name: "empty", oid: ""},
		{name: "only a dot", oid: "."},
		{name: "empty component", oid: "1..2"},
		{name: "leading dot", oid: ".1"},
		{name: "trailing dot", oid: "1."},
		{name: "non-numeric component", oid: "1.a.2"},
		{name: "hexadecimal component", oid: "0x10"},
		{name: "whitespace", oid: "1. 2"},
		{name: "negative component", oid: "1.-5.2"},
		{name: "negative zero", oid: "-0"},
		{name: "explicit plus sign", oid: "+5"},
		{name: "leading zero", oid: "05"},
		{name: "component exceeds int32", oid: "2147483648"},
		{name: "component exceeds int64", oid: "9223372036854775808"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := FromString(tc.oid)
			if err == nil {
				t.Errorf("FromString(%q) = %q, want error", tc.oid, got)
			}
		})
	}
}

func TestFromBytesInvalid(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		encoded []byte
	}{
		{name: "nil input", encoded: nil},
		{name: "empty input", encoded: []byte{}},
		{name: "truncated only component", encoded: []byte{0x81}},
		{name: "truncated last component", encoded: []byte{0x55, 0x81}},
		{name: "non-minimal zero", encoded: []byte{0x80, 0x00}},
		{name: "non-minimal first component", encoded: []byte{0x80, 0x01, 0x02}},
		{name: "non-minimal middle component", encoded: []byte{0x55, 0x80, 0x02}},
		{name: "exceeds int32", encoded: []byte{0x88, 0x80, 0x80, 0x80, 0x00}},
		{name: "six-byte component", encoded: []byte{0x81, 0x80, 0x80, 0x80, 0x80, 0x00}},
		{name: "oversized truncated component", encoded: []byte{0x55, 0x02, 0xc0, 0x80, 0x80, 0x80, 0x80}},
		{
			// 2^70 + 1, which a decoder without a length limit could wrap
			// around to 1.
			name:    "wraps int64",
			encoded: []byte{0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := FromBytes(tc.encoded)
			if err == nil {
				t.Errorf("FromBytes(%x) = %q, want error", tc.encoded, got)
			}
		})
	}
}
