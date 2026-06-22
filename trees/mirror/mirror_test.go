package mirror

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

func hashN(b byte) tlog.Hash {
	var h tlog.Hash
	h[0] = b
	return h
}

func entry(i int64) []byte {
	return fmt.Appendf(nil, "entry-%d", i)
}

// buildAddEntries constructs a request whose packages match the canonical
// sequence for the interval, so it round-trips through Marshal and Parse.
func buildAddEntries(origin string, uploadStart, uploadEnd int64, ticket []byte) AddEntriesRequest {
	var packages []EntryPackage
	for _, p := range EntryPackages(uploadStart, uploadEnd) {
		entries := make([][]byte, p.End-p.EntriesStart)
		for j := range entries {
			entries[j] = entry(p.EntriesStart + int64(j))
		}
		packages = append(packages, EntryPackage{
			Entries: entries,
			Proof:   []tlog.Hash{hashN(byte(p.SubtreeStart)), hashN(byte(p.End))},
		})
	}
	return AddEntriesRequest{
		Origin:      origin,
		UploadStart: uploadStart,
		UploadEnd:   uploadEnd,
		Ticket:      ticket,
		Packages:    packages,
	}
}

// TestAddEntriesRoundTrip uses an interval that does not start on a 256
// boundary, so the first package carries fewer entries than its subtree spans.
func TestAddEntriesRoundTrip(t *testing.T) {
	req := buildAddEntries("oid/1.3.6.1.4.1.32473.2.0.42", 100, 300, []byte("ticket"))
	body, err := req.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %s", err)
	}
	got, truncated, err := ParseAddEntriesRequest(body)
	if err != nil {
		t.Fatalf("ParseAddEntriesRequest: %s", err)
	}
	if truncated {
		t.Error("ParseAddEntriesRequest reported a complete body as truncated")
	}
	if !reflect.DeepEqual(got, req) {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, req)
	}
}

// TestAddEntriesPrefix checks that a body carrying a strict prefix of the
// canonical sequence parses to exactly those packages.
func TestAddEntriesPrefix(t *testing.T) {
	full := buildAddEntries("example.com/log", 0, 600, []byte("t"))
	prefix := full
	prefix.Packages = full.Packages[:1]

	body, err := prefix.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %s", err)
	}
	got, truncated, err := ParseAddEntriesRequest(body)
	if err != nil {
		t.Fatalf("ParseAddEntriesRequest: %s", err)
	}
	if truncated {
		t.Error("a clean package prefix is not a truncated body")
	}
	if len(got.Packages) != 1 {
		t.Fatalf("parsed %d packages, want 1", len(got.Packages))
	}
	if !reflect.DeepEqual(got, prefix) {
		t.Error("prefix round-trip mismatch")
	}
}

// TestAddEntriesTruncatedPackage: a body cut mid-package parses to the complete
// prefix with truncated set, per tlog-mirror's discard-partial- bytes
// requirement; a first-package cut yields zero packages (the 400 case).
func TestAddEntriesTruncatedPackage(t *testing.T) {
	full := buildAddEntries("example.com/log", 0, 300, []byte("t"))
	body, err := full.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %s", err)
	}

	got, truncated, err := ParseAddEntriesRequest(body[:len(body)-1])
	if err != nil {
		t.Fatalf("ParseAddEntriesRequest of a truncated body: %s", err)
	}
	if !truncated {
		t.Error("truncated = false for a body cut mid-package")
	}
	if len(got.Packages) != 1 {
		t.Errorf("parsed %d packages, want the 1 complete package before the cut", len(got.Packages))
	}
	if !reflect.DeepEqual(got.Packages[0], full.Packages[0]) {
		t.Error("the complete package before the cut did not survive")
	}

	// Cut inside the first package: nothing complete to return.
	prefixOnly, err := AddEntriesRequest{Origin: full.Origin, UploadStart: 0, UploadEnd: 300, Ticket: []byte("t")}.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %s", err)
	}
	got, truncated, err = ParseAddEntriesRequest(append(bytes.Clone(prefixOnly), 0x00))
	if err != nil {
		t.Fatalf("ParseAddEntriesRequest of a first-package cut: %s", err)
	}
	if !truncated || len(got.Packages) != 0 {
		t.Errorf("first-package cut: truncated = %v with %d packages, want true with 0", truncated, len(got.Packages))
	}
}

func TestAddEntriesRejectsMalformed(t *testing.T) {
	body, err := buildAddEntries("example.com/log", 0, 300, []byte("t")).Marshal()
	if err != nil {
		t.Fatalf("Marshal: %s", err)
	}

	_, _, err = ParseAddEntriesRequest(body[:5])
	if err == nil {
		t.Error("truncated header: want error")
	}
	// Bytes past the canonical sequence are structural, not interruption.
	_, _, err = ParseAddEntriesRequest(append(bytes.Clone(body), 0xff))
	if err == nil {
		t.Error("trailing data: want error")
	}
}

// TestAddEntriesMarshalRejectsBadHeader: header validation must hold even with
// no packages, where the per-package checks cannot catch a bad interval.
func TestAddEntriesMarshalRejectsBadHeader(t *testing.T) {
	cases := []struct {
		name string
		req  AddEntriesRequest
	}{
		{"Negative upload start", AddEntriesRequest{Origin: "x", UploadStart: -1, UploadEnd: 0}},
		{"Start past end", AddEntriesRequest{Origin: "x", UploadStart: 5, UploadEnd: 4}},
		{"Empty origin", AddEntriesRequest{UploadStart: 0, UploadEnd: 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.req.Marshal()
			if err == nil {
				t.Error("want error")
			}
		})
	}
}

// TestAddEntriesEmptyProofPackage: num_hashes 0 is a legitimate wire shape,
// since SUBTREE_PROOF is empty when the package subtree is the whole tree.
func TestAddEntriesEmptyProofPackage(t *testing.T) {
	req := AddEntriesRequest{
		Origin:      "example.com/log",
		UploadStart: 0,
		UploadEnd:   2,
		Packages:    []EntryPackage{{Entries: [][]byte{entry(0), entry(1)}, Proof: []tlog.Hash{}}},
	}
	body, err := req.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %s", err)
	}
	got, truncated, err := ParseAddEntriesRequest(body)
	if err != nil || truncated {
		t.Fatalf("ParseAddEntriesRequest = truncated %v, err %v", truncated, err)
	}
	if len(got.Packages) != 1 || len(got.Packages[0].Proof) != 0 || len(got.Packages[0].Entries) != 2 {
		t.Errorf("round-trip = %+v, want one 2-entry package with an empty proof", got.Packages)
	}
}

// TestAddEntriesHugeIntervalBounded checks that a tiny body with an enormous
// interval does not try to build the whole canonical sequence; it parses to
// zero packages quickly rather than allocating its way to an OOM.
func TestAddEntriesHugeIntervalBounded(t *testing.T) {
	req := AddEntriesRequest{Origin: "x", UploadStart: 0, UploadEnd: 1 << 50, Ticket: []byte("t")}
	body, err := req.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %s", err)
	}
	got, truncated, err := ParseAddEntriesRequest(body)
	if err != nil {
		t.Fatalf("ParseAddEntriesRequest: %s", err)
	}
	if truncated {
		t.Error("a header-only body is not truncated")
	}
	if len(got.Packages) != 0 {
		t.Errorf("parsed %d packages, want 0", len(got.Packages))
	}
}

// TestAddEntriesMarshalRejectsMismatch checks that Marshal refuses packages
// that do not match the canonical sequence, which the receiving side would
// otherwise split at the wrong boundaries. The interval [0, 2) has one
// canonical 2-entry package.
func TestAddEntriesMarshalRejectsMismatch(t *testing.T) {
	wrongCount := AddEntriesRequest{
		Origin: "x", UploadStart: 0, UploadEnd: 2,
		Packages: []EntryPackage{{Entries: [][]byte{entry(0)}}},
	}
	_, err := wrongCount.Marshal()
	if err == nil {
		t.Error("wrong entry count: want error")
	}

	tooMany := AddEntriesRequest{
		Origin: "x", UploadStart: 0, UploadEnd: 2,
		Packages: []EntryPackage{
			{Entries: [][]byte{entry(0), entry(1)}},
			{Entries: [][]byte{entry(2)}},
		},
	}
	_, err = tooMany.Marshal()
	if err == nil {
		t.Error("too many packages: want error")
	}
}

func TestAddCheckpointRoundTrip(t *testing.T) {
	// A checkpoint note carries its own blank line between its text and its
	// signatures; Parse must split on the request's blank line, not that one.
	checkpoint := []byte("example.com/log\n300\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n\n— example.com/log AAAA\n")
	cases := []struct {
		name string
		req  AddCheckpointRequest
	}{
		{
			name: "With proof",
			req: AddCheckpointRequest{
				OldSize:    200,
				Proof:      []tlog.Hash{hashN(1), hashN(2), hashN(3)},
				Checkpoint: checkpoint,
			},
		},
		{
			// tlog-witness: the proof MUST be empty when the old size is zero,
			// the shape of every first contact.
			name: "Old size zero, empty proof",
			req: AddCheckpointRequest{
				OldSize:    0,
				Checkpoint: checkpoint,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := tc.req.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %s", err)
			}
			got, err := ParseAddCheckpointRequest(body)
			if err != nil {
				t.Fatalf("ParseAddCheckpointRequest: %s", err)
			}
			// An empty proof parses as an empty non-nil slice; normalize before
			// comparing.
			if len(got.Proof) == 0 {
				got.Proof = nil
			}
			if !reflect.DeepEqual(got, tc.req) {
				t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, tc.req)
			}
		})
	}
}

func TestAddCheckpointMarshalRejects(t *testing.T) {
	cases := []struct {
		name string
		req  AddCheckpointRequest
	}{
		{"Negative old size", AddCheckpointRequest{OldSize: -1, Checkpoint: []byte("x\n")}},
		{"64 proof hashes", AddCheckpointRequest{OldSize: 5, Proof: make([]tlog.Hash, 64), Checkpoint: []byte("x\n")}},
		{"Empty checkpoint", AddCheckpointRequest{OldSize: 5}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.req.Marshal()
			if err == nil {
				t.Error("want error")
			}
		})
	}
}

func TestParseAddCheckpointRejects(t *testing.T) {
	// Decodes to the same 32 bytes as the canonical form, but is not what
	// Marshal would emit.
	canonical := hashN(1).String()
	nonCanonical := canonical[:len(canonical)-2] + "B="

	cp := "example.com/log\n1\nAAAA\n\n— x y\n"
	cases := []struct {
		name string
		body string
	}{
		{"No blank line", "old 5\nhash\n"},
		{"Missing old line", "5\n\n" + cp},
		{"Leading zero old size", "old 05\n\n" + cp},
		{"Negative old size", "old -1\n\n" + cp},
		{"Bad proof hash", "old 0\nnotahash\n\n" + cp},
		{"Non-canonical proof hash", "old 0\n" + nonCanonical + "\n\n" + cp},
		{"Empty checkpoint", "old 5\n\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseAddCheckpointRequest([]byte(tc.body))
			if err == nil {
				t.Error("want error")
			}
		})
	}
}

// TestParseAddEntriesRejectsEmptyOrigin hand-builds a header with a zero-length
// origin, which Marshal can no longer produce.
func TestParseAddEntriesRejectsEmptyOrigin(t *testing.T) {
	body := make([]byte, 20) // u16 origin len 0, u64 start 0, u64 end 0, u16 ticket len 0
	_, _, err := ParseAddEntriesRequest(body)
	if err == nil {
		t.Error("empty origin: want error")
	}
}

func TestParseAddCheckpointRejectsTooManyProofLines(t *testing.T) {
	var b strings.Builder
	b.WriteString("old 5\n")
	for i := range 64 {
		b.WriteString(hashN(byte(i)).String())
		b.WriteByte('\n')
	}
	b.WriteString("\nexample.com/log\n1\nAAAA\n")
	_, err := ParseAddCheckpointRequest([]byte(b.String()))
	if err == nil {
		t.Error("64 proof lines: want error")
	}
}

func TestSizeRoundTrip(t *testing.T) {
	for _, size := range []int64{0, 1, 20852163} {
		body, err := MarshalSize(size)
		if err != nil {
			t.Fatalf("MarshalSize: %s", err)
		}
		got, err := ParseSize(body)
		if err != nil {
			t.Fatalf("ParseSize: %s", err)
		}
		if got != size {
			t.Errorf("ParseSize round-trip = %d, want %d", got, size)
		}
	}

	_, err := MarshalSize(-1)
	if err == nil {
		t.Error("MarshalSize(-1) = nil error, want error")
	}
}

func TestParseSizeRejects(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"No newline", "5"},
		{"Non-numeric", "abc\n"},
		{"Negative", "-1\n"},
		{"Leading zero", "007\n"},
		{"Plus sign", "+5\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSize([]byte(tc.body))
			if err == nil {
				t.Error("want error")
			}
		})
	}
}

func TestMirrorInfoRoundTrip(t *testing.T) {
	for _, m := range []Info{
		{TreeSize: 300, NextEntry: 256, Ticket: []byte("ticket")},
		{TreeSize: 0, NextEntry: 0, Ticket: nil},
	} {
		body, err := m.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %s", err)
		}
		got, err := ParseMirrorInfo(body)
		if err != nil {
			t.Fatalf("ParseMirrorInfo: %s", err)
		}
		if got.TreeSize != m.TreeSize || got.NextEntry != m.NextEntry || !bytes.Equal(got.Ticket, m.Ticket) {
			t.Errorf("ParseMirrorInfo round-trip = %+v, want %+v", got, m)
		}
	}

	for _, m := range []Info{
		{TreeSize: -1, NextEntry: 0},
		{TreeSize: 0, NextEntry: -1},
	} {
		_, err := m.Marshal()
		if err == nil {
			t.Errorf("Marshal(%+v) = nil error, want error", m)
		}
	}
}

func TestParseMirrorInfoRejects(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"No newline", "1\n2\nAAAA"},
		{"Too few lines", "1\n2\n"},
		{"Bad ticket", "1\n2\n!!!\n"},
		// "AB==" decodes (Go ignores the non-zero trailing bit) but is not the
		// canonical encoding of its byte, which is "AA==".
		{"Non-canonical ticket", "1\n2\nAB==\n"},
		{"Negative size", "-1\n2\nAAAA\n"},
		{"Leading zero next entry", "1\n02\nAAAA\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseMirrorInfo([]byte(tc.body))
			if err == nil {
				t.Error("want error")
			}
		})
	}
}

func TestEntryPackages(t *testing.T) {
	cases := []struct {
		name       string
		start, end int64
		expect     []Package
	}{
		{"Empty interval", 0, 0, nil},
		{"Empty interval at offset", 5, 5, nil},
		{"Single full bundle", 0, 256, []Package{{0, 0, 256}}},
		{"Full plus partial", 0, 300, []Package{{0, 0, 256}, {256, 256, 300}}},
		{"Unaligned start", 100, 300, []Package{{0, 100, 256}, {256, 256, 300}}},
		{"Aligned second bundle", 256, 512, []Package{{256, 256, 512}}},
		{"Multi bundle", 300, 800, []Package{{256, 300, 512}, {512, 512, 768}, {768, 768, 800}}},
		{"Single entry straddle", 255, 257, []Package{{0, 255, 256}, {256, 256, 257}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EntryPackages(tc.start, tc.end)
			if !slices.Equal(got, tc.expect) {
				t.Errorf("EntryPackages(%d, %d) = %v, want %v", tc.start, tc.end, got, tc.expect)
			}
		})
	}
}

// TestEntryPackageAt covers sequence bounds, invalid inputs, and the doc
// comment's int64-safety claim at the top of the range, where naive rounded-end
// or base+width math would overflow.
func TestEntryPackageAt(t *testing.T) {
	const maxInt64 = int64(^uint64(0) >> 1)

	t.Run("Out of sequence", func(t *testing.T) {
		cases := []struct {
			name          string
			start, end, i int64
		}{
			{"Index past sequence", 0, 256, 1},
			{"Negative index", 0, 256, -1},
			{"Empty interval", 5, 5, 0},
			{"Inverted interval", 6, 5, 0},
			{"Negative start", -1, 256, 0},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, ok := EntryPackageAt(tc.start, tc.end, tc.i)
				if ok {
					t.Errorf("EntryPackageAt(%d, %d, %d) = ok, want not ok", tc.start, tc.end, tc.i)
				}
			})
		}
	})

	t.Run("Near MaxInt64", func(t *testing.T) {
		alignedTop := maxInt64 / 256 * 256
		p, ok := EntryPackageAt(maxInt64-1, maxInt64, 0)
		if !ok {
			t.Fatalf("EntryPackageAt(%d, %d, 0) = not ok", maxInt64-1, maxInt64)
		}
		want := Package{SubtreeStart: alignedTop, EntriesStart: maxInt64 - 1, End: maxInt64}
		if p != want {
			t.Errorf("EntryPackageAt(%d, %d, 0) = %+v, want %+v", maxInt64-1, maxInt64, p, want)
		}
		_, ok = EntryPackageAt(maxInt64-1, maxInt64, 1)
		if ok {
			t.Error("index 1 past the single-package sequence = ok, want not ok")
		}

		// base+TileWidth is computed here and must not wrap.
		p, ok = EntryPackageAt(alignedTop-256, alignedTop, 0)
		if !ok {
			t.Fatalf("EntryPackageAt(%d, %d, 0) = not ok", alignedTop-256, alignedTop)
		}
		want = Package{SubtreeStart: alignedTop - 256, EntriesStart: alignedTop - 256, End: alignedTop}
		if p != want {
			t.Errorf("EntryPackageAt(%d, %d, 0) = %+v, want %+v", alignedTop-256, alignedTop, p, want)
		}
	})
}
