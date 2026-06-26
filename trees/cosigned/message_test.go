package cosigned

import (
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

func TestMessageRoundtrip(t *testing.T) {
	m := Message{
		CosignerName: "alpha",
		Timestamp:    1234,
		LogOrigin:    "beta",
		Start:        999,
		End:          1000,
		SubtreeHash:  [32]byte{},
	}

	copy(m.SubtreeHash[:], []byte("0123456789abcdef0123456789abcdef"))

	out, err := m.Marshal()
	if err != nil {
		t.Fatalf("marshaling: %s", err)
	}

	var m2 Message

	err = m2.Unmarshal(out)
	if err != nil {
		t.Fatalf("unmarshaling encoded message: %s", err)
	}

	if !reflect.DeepEqual(m, m2) {
		t.Errorf("round-tripping message: got %#v, want %#v",
			m, m2)
	}
}

func TestMarshalErrors(t *testing.T) {
	m := Message{
		CosignerName: "Michigan",
		Timestamp:    1337000,
		LogOrigin:    "Illinois",
		Start:        9,
		End:          87654321,
		SubtreeHash:  [32]byte{},
	}

	type testCase struct {
		name, expected string
		distorter      func(target *Message)
	}

	testCases := []testCase{
		{"short CosignerName", "invalid cosigner_name length 0", func(target *Message) {
			target.CosignerName = ""
		}},
		{"long CosignerName", "invalid cosigner_name length 256", func(target *Message) {
			target.CosignerName = strings.Repeat("a", 256)
		}},
		{"short LogOrigin", "invalid log_origin length 0", func(target *Message) {
			target.LogOrigin = ""
		}},
		{"long LogOrigin", "invalid log_origin length 256", func(target *Message) {
			target.LogOrigin = strings.Repeat("a", 256)
		}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m2 := m
			tc.distorter(&m2)
			_, err := m2.Marshal()
			if err == nil {
				t.Fatalf("got no error, want %q", tc.expected)
			}
			if err.Error() != tc.expected {
				t.Errorf("marshal with short name: got %q, want %q", err, tc.expected)
			}
		})
	}
}

func TestUnmarshalErrors(t *testing.T) {
	m := Message{
		CosignerName: "Debut",
		Timestamp:    55555,
		LogOrigin:    "Post",
		Start:        11,
		End:          22,
		SubtreeHash:  [32]byte{},
	}

	out, err := m.Marshal()
	if err != nil {
		t.Fatalf("marshal: %s", err)
	}
	t.Logf("%x", out)

	var m2 Message
	err = m2.Unmarshal(out[:len(out)-1])
	if err == nil {
		t.Errorf("unmarshal with short input: got no error")
	}

	long := append(out, byte('a'))
	err = m2.Unmarshal(long)
	if err == nil {
		t.Errorf("unmarshal with trailing bytes: got no error")
	}

	emptyCosigner, err := hex.DecodeString("737562747265652f76310a0000000000000000d90304506f7374000000000000000b00000000000000160000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Errorf("decoding hex: %s", err)
	}
	err = m2.Unmarshal(emptyCosigner)
	if err == nil {
		t.Errorf("unmarshal with empty cosigner_name: got no error")
	}

	emptyLogOrigin, err := hex.DecodeString("737562747265652f76310a00054465627574000000000000d90300000000000000000b00000000000000160000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Errorf("decoding hex: %s", err)
	}
	err = m2.Unmarshal(emptyLogOrigin)
	if err == nil {
		t.Errorf("unmarshal with empty log_origin: got no error")
	}
}
