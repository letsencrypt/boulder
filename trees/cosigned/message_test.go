package cosigned

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"

	"github.com/letsencrypt/boulder/trees"
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

	m2, err := unmarshal(out)
	if err != nil {
		t.Fatalf("unmarshaling encoded message: %s", err)
	}

	if !reflect.DeepEqual(m, *m2) {
		t.Errorf("round-tripping message: got %#v, want %#v", m, *m2)
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
		{"negative Start", "start is out of range: -1", func(target *Message) {
			target.Start = -1
		}},
		{"too-large Start", "start is out of range: 281474976710656", func(target *Message) {
			target.Start = trees.MaxSize + 1
		}},
		{"negative End", "end is out of range: -1", func(target *Message) {
			target.End = -1
		}},
		{"too-large End", "end is out of range: 281474976710656", func(target *Message) {
			target.End = trees.MaxSize + 1
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

// unmarshal unmarshals the input bytes and returns a *Message.
func unmarshal(input []byte) (*Message, error) {
	var out Message

	s := cryptobyte.String(input)
	var label []byte
	if !s.ReadBytes(&label, len(subtreeLabel)) {
		return nil, errors.New("invalid label")
	}
	if !bytes.Equal(label, []byte(subtreeLabel)) {
		return nil, errors.New("label was not subtree/v1")
	}

	var cosignerName cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&cosignerName) {
		return nil, errors.New("invalid cosigner_name")
	}
	if len(cosignerName) < 1 {
		return nil, errors.New("empty cosigner_name")
	}
	out.CosignerName = string(cosignerName)

	if !s.ReadUint64(&out.Timestamp) {
		return nil, errors.New("invalid timestamp")
	}

	var logOrigin cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&logOrigin) {
		return nil, errors.New("invalid log_origin")
	}
	if len(logOrigin) < 1 {
		return nil, errors.New("empty log_origin")
	}
	out.LogOrigin = string(logOrigin)

	var start, end uint64
	if !s.ReadUint64(&start) {
		return nil, errors.New("invalid start")
	}
	if start > trees.MaxSize {
		return nil, fmt.Errorf("start %d out of range", start)
	}
	out.Start = int64(start)

	if !s.ReadUint64(&end) {
		return nil, errors.New("invalid end")
	}
	if end > trees.MaxSize {
		return nil, fmt.Errorf("end %d out of range", end)
	}
	out.End = int64(end)

	var subtreeHash []byte
	if !s.ReadBytes(&subtreeHash, len(out.SubtreeHash)) {
		return nil, errors.New("invalid subtree hash")
	}
	copy(out.SubtreeHash[:], subtreeHash)

	if !s.Empty() {
		return nil, errors.New("trailing bytes")
	}

	return &out, nil
}
