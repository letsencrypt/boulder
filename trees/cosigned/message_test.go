package cosigned

import (
	"encoding/binary"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

// TestMessageLayout pins the wire layout against a hand-assembled byte
// sequence: 12-byte label, length-prefixed name, big-endian timestamp,
// length-prefixed origin, big-endian start and end, 32-byte hash.
func TestMessageLayout(t *testing.T) {
	var hash tlog.Hash
	copy(hash[:], []byte("0123456789abcdef0123456789abcdef"))
	m := Message{
		CosignerName: "mirror.test/m1",
		Timestamp:    1679315147,
		LogOrigin:    "example.com/log",
		Start:        0,
		End:          20852163,
		SubtreeHash:  hash,
	}

	var want []byte
	want = append(want, "subtree/v1\n\x00"...)
	want = append(want, byte(len(m.CosignerName)))
	want = append(want, m.CosignerName...)
	want = binary.BigEndian.AppendUint64(want, m.Timestamp)
	want = append(want, byte(len(m.LogOrigin)))
	want = append(want, m.LogOrigin...)
	want = binary.BigEndian.AppendUint64(want, m.Start)
	want = binary.BigEndian.AppendUint64(want, m.End)
	want = append(want, hash[:]...)

	got, err := m.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %s", err)
	}
	if string(got) != string(want) {
		t.Errorf("Marshal = %x,\n   want %x", got, want)
	}
}

func TestMessageRoundTrip(t *testing.T) {
	var hash tlog.Hash
	copy(hash[:], []byte("0123456789abcdef0123456789abcdef"))
	m := Message{
		CosignerName: "alpha",
		Timestamp:    1234,
		LogOrigin:    "beta",
		Start:        999,
		End:          1000,
		SubtreeHash:  hash,
	}

	out, err := m.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %s", err)
	}

	var got Message
	err = got.Unmarshal(out)
	if err != nil {
		t.Fatalf("Unmarshal: %s", err)
	}
	if !reflect.DeepEqual(m, got) {
		t.Errorf("round trip: got %#v, want %#v", got, m)
	}
}

func TestMessageMarshalErrors(t *testing.T) {
	var hash tlog.Hash
	cases := []struct {
		name    string
		message Message
	}{
		{"Empty cosigner name", Message{CosignerName: "", LogOrigin: "x", SubtreeHash: hash}},
		{"Oversize cosigner name", Message{CosignerName: strings.Repeat("a", 256), LogOrigin: "x", SubtreeHash: hash}},
		{"Empty log origin", Message{CosignerName: "x", LogOrigin: "", SubtreeHash: hash}},
		{"Oversize log origin", Message{CosignerName: "x", LogOrigin: strings.Repeat("a", 256), SubtreeHash: hash}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.message.Marshal()
			if err == nil {
				t.Error("Marshal = nil error, want error")
			}
		})
	}
}

func TestMessageUnmarshalErrors(t *testing.T) {
	var hash tlog.Hash
	valid, err := (&Message{
		CosignerName: "alpha",
		Timestamp:    55,
		LogOrigin:    "beta",
		Start:        11,
		End:          22,
		SubtreeHash:  hash,
	}).Marshal()
	if err != nil {
		t.Fatalf("Marshal: %s", err)
	}

	var m Message

	err = m.Unmarshal(valid[:len(valid)-1])
	if err == nil {
		t.Error("Unmarshal of a truncated message = nil error, want error")
	}

	long := append(append([]byte(nil), valid...), 'x')
	err = m.Unmarshal(long)
	if err == nil {
		t.Error("Unmarshal with trailing bytes = nil error, want error")
	}

	badLabel := append([]byte(nil), valid...)
	badLabel[0] = 'X'
	err = m.Unmarshal(badLabel)
	if err == nil {
		t.Error("Unmarshal with a wrong label = nil error, want error")
	}

	emptyName := append([]byte(nil), valid...)
	emptyName[len(subtreeLabel)] = 0 // zero the cosigner_name length prefix
	err = m.Unmarshal(emptyName)
	if err == nil {
		t.Error("Unmarshal with an empty cosigner_name = nil error, want error")
	}
}
