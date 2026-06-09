package tlog

import (
	"bytes"
	"testing"
)

func TestEntryBundleRoundTrip(t *testing.T) {
	entries := [][]byte{{}, {0x01}, []byte("hello"), bytes.Repeat([]byte{0xab}, 1000)}
	var bundle []byte
	for _, e := range entries {
		var err error
		bundle, err = AppendEntry(bundle, e)
		if err != nil {
			t.Fatalf("AppendEntry: %s", err)
		}
	}

	got, err := ParseEntryBundle(bundle)
	if err != nil {
		t.Fatalf("ParseEntryBundle: %s", err)
	}
	if len(got) != len(entries) {
		t.Fatalf("ParseEntryBundle returned %d entries, want %d", len(got), len(entries))
	}
	for i := range entries {
		if !bytes.Equal(got[i], entries[i]) {
			t.Errorf("entry %d = %x, want %x", i, got[i], entries[i])
		}
	}
}

// TestParseEntryBundleCopies confirms parsed entries do not alias the input
// buffer, so mutating the buffer afterward cannot corrupt them.
func TestParseEntryBundleCopies(t *testing.T) {
	bundle, err := AppendEntry(nil, []byte("entry"))
	if err != nil {
		t.Fatalf("AppendEntry: %s", err)
	}
	got, err := ParseEntryBundle(bundle)
	if err != nil {
		t.Fatalf("ParseEntryBundle: %s", err)
	}
	for i := range bundle {
		bundle[i] = 0xff
	}
	if !bytes.Equal(got[0], []byte("entry")) {
		t.Errorf("parsed entry changed after mutating the bundle: %x", got[0])
	}
}

func TestParseEntryBundleRejects(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"Truncated length prefix", []byte{0x00}},
		// Length says 5, only 1 byte follows
		{"Truncated entry", []byte{0x00, 0x05, 0x01}},
		// A bundle is the entry form of a tile of width 1..TileWidth, and
		// tlog-tiles says empty tiles MUST NOT be served, so an empty
		// bundle is not a valid resource.
		{"Empty bundle", nil},
		{"Empty bundle (non-nil)", []byte{}},
	}
	for _, tc := range cases {
		_, err := ParseEntryBundle(tc.data)
		if err == nil {
			t.Errorf("ParseEntryBundle(%s) = nil error, want error", tc.name)
		}
	}
}

// TestParseEntryBundleEntryCount pins the tlog-tiles bundle width bounds: a
// full bundle of TileWidth entries parses, one more entry is rejected.
func TestParseEntryBundleEntryCount(t *testing.T) {
	var bundle []byte
	var err error
	for range TileWidth {
		bundle, err = AppendEntry(bundle, []byte{0xaa})
		if err != nil {
			t.Fatalf("AppendEntry: %s", err)
		}
	}

	got, err := ParseEntryBundle(bundle)
	if err != nil {
		t.Fatalf("ParseEntryBundle of a full bundle: %s", err)
	}
	if len(got) != TileWidth {
		t.Fatalf("ParseEntryBundle returned %d entries, want %d", len(got), TileWidth)
	}

	bundle, err = AppendEntry(bundle, []byte{0xbb})
	if err != nil {
		t.Fatalf("AppendEntry: %s", err)
	}
	_, err = ParseEntryBundle(bundle)
	if err == nil {
		t.Errorf("ParseEntryBundle of a %d-entry bundle = nil error, want error", TileWidth+1)
	}
}

func TestAppendEntryRejectsOversize(t *testing.T) {
	_, err := AppendEntry(nil, make([]byte, 65536))
	if err == nil {
		t.Error("AppendEntry of a 65536-byte entry = nil error, want error")
	}
}
