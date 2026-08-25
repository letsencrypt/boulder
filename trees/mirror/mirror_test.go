package mirror

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/tlog"
)

func mustHash(t *testing.T, s string) tlog.Hash {
	t.Helper()
	h, err := tlog.ParseHash(s)
	if err != nil {
		t.Fatalf("ParseHash(%q): %s", s, err)
	}
	return h
}

// TestAddCheckpointRequest pins the request body to the worked example in
// c2sp.org/tlog-witness.
func TestAddCheckpointRequest(t *testing.T) {
	checkpoint := "example.com/behind-the-sofa\n" +
		"20852163\n" +
		"CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n" +
		"\n" +
		"— example.com/behind-the-sofa Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8=\n"
	proof := []tlog.Hash{
		mustHash(t, "PlRNCrwHpqhGrupue0L7gxbjbMiKA9temvuZZDDpkaw="),
		mustHash(t, "jrJZDmY8Y7SyJE0MWLpLozkIVMSMZcD5kvuKxPC3swk="),
		mustHash(t, "5+pKlUdi2LeF/BcMHBn+Ku6yhPGNCswZZD1X/6QgPd8="),
		mustHash(t, "/6WVhPs2CwSsb5rYBH5cjHV/wSmA79abXAwhXw3Kj/0="),
	}

	body, err := AddCheckpointRequest(20852014, proof, []byte(checkpoint))
	if err != nil {
		t.Fatalf("AddCheckpointRequest: %s", err)
	}
	expect := "old 20852014\n" +
		"PlRNCrwHpqhGrupue0L7gxbjbMiKA9temvuZZDDpkaw=\n" +
		"jrJZDmY8Y7SyJE0MWLpLozkIVMSMZcD5kvuKxPC3swk=\n" +
		"5+pKlUdi2LeF/BcMHBn+Ku6yhPGNCswZZD1X/6QgPd8=\n" +
		"/6WVhPs2CwSsb5rYBH5cjHV/wSmA79abXAwhXw3Kj/0=\n" +
		"\n" +
		checkpoint
	if string(body) != expect {
		t.Errorf("AddCheckpointRequest = %q, want %q", body, expect)
	}
}

func TestAddCheckpointRequestRejects(t *testing.T) {
	checkpoint := []byte("origin\n1\nhash\n")
	_, err := AddCheckpointRequest(-1, nil, checkpoint)
	if err == nil {
		t.Error("AddCheckpointRequest with a negative old size = nil error, want error")
	}
	_, err = AddCheckpointRequest(0, make([]tlog.Hash, 1), checkpoint)
	if err == nil {
		t.Error("AddCheckpointRequest with a proof and old size zero = nil error, want error")
	}
	_, err = AddCheckpointRequest(1, make([]tlog.Hash, 64), checkpoint)
	if err == nil {
		t.Error("AddCheckpointRequest with 64 proof lines = nil error, want error")
	}
	_, err = AddCheckpointRequest(1, nil, nil)
	if err == nil {
		t.Error("AddCheckpointRequest with an empty checkpoint = nil error, want error")
	}
}

func TestParseSizeResponse(t *testing.T) {
	size, err := ParseSizeResponse([]byte("20852014\n"))
	if err != nil {
		t.Fatalf("ParseSizeResponse: %s", err)
	}
	if size != 20852014 {
		t.Errorf("ParseSizeResponse = %d, want 20852014", size)
	}

	size, err = ParseSizeResponse([]byte("0512\n"))
	if err != nil {
		t.Fatalf("ParseSizeResponse with a leading zero: %s", err)
	}
	if size != 512 {
		t.Errorf("ParseSizeResponse = %d, want 512", size)
	}

	for _, malformed := range []string{"", "512", "512\n\n", "+1\n", "-1\n", "1 2\n"} {
		_, err := ParseSizeResponse([]byte(malformed))
		if err == nil {
			t.Errorf("ParseSizeResponse(%q) = nil error, want error", malformed)
		}
	}
}

func TestParseMirrorInfo(t *testing.T) {
	info, err := ParseMirrorInfo([]byte("512\n300\ndGlja2V0\n"))
	if err != nil {
		t.Fatalf("ParseMirrorInfo: %s", err)
	}
	expect := MirrorInfo{TreeSize: 512, NextEntry: 300, Ticket: []byte("ticket")}
	if !reflect.DeepEqual(info, expect) {
		t.Errorf("ParseMirrorInfo = %+v, want %+v", info, expect)
	}

	// A zero length ticket is valid, and parses to an empty ticket.
	info, err = ParseMirrorInfo([]byte("512\n300\n\n"))
	if err != nil {
		t.Fatalf("ParseMirrorInfo with an empty ticket: %s", err)
	}
	if len(info.Ticket) != 0 {
		t.Errorf("Ticket = %q, want empty", info.Ticket)
	}

	for _, malformed := range []string{"", "512\n300\n", "512\n300\ndGlja2V0", "512\n300\n!!!\n", "512\n-1\n\n", "512\n300\n\n\n"} {
		_, err := ParseMirrorInfo([]byte(malformed))
		if err == nil {
			t.Errorf("ParseMirrorInfo(%q) = nil error, want error", malformed)
		}
	}
}

func TestPackages(t *testing.T) {
	for _, tc := range []struct {
		name   string
		start  int64
		end    int64
		max    int64
		expect []Package
	}{
		{"empty", 5, 5, 32, nil},
		{"single aligned", 0, 256, 32, []Package{{0, 0, 256}}},
		{"single short", 0, 5, 32, []Package{{0, 0, 5}}},
		{"unaligned start", 300, 700, 32, []Package{{256, 300, 512}, {512, 512, 700}}},
		{"aligned interior", 256, 768, 32, []Package{{256, 256, 512}, {512, 512, 768}}},
		{"start and end in same package", 300, 400, 32, []Package{{256, 300, 400}}},
		{"truncated to max", 0, 1000, 2, []Package{{0, 0, 256}, {256, 256, 512}}},
		{"unaligned truncated to max", 300, 2000, 2, []Package{{256, 300, 512}, {512, 512, 768}}},
		{"exactly max", 0, 512, 2, []Package{{0, 0, 256}, {256, 256, 512}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packages, err := Packages(tc.start, tc.end, tc.max)
			if err != nil {
				t.Fatalf("Packages(%d, %d, %d): %s", tc.start, tc.end, tc.max, err)
			}
			if !reflect.DeepEqual(packages, tc.expect) {
				t.Errorf("Packages(%d, %d, %d) = %+v, want %+v", tc.start, tc.end, tc.max, packages, tc.expect)
			}
		})
	}

	_, err := Packages(-1, 5, 32)
	if err == nil {
		t.Error("Packages(-1, 5, 32) = nil error, want error")
	}
	_, err = Packages(6, 5, 32)
	if err == nil {
		t.Error("Packages(6, 5, 32) = nil error, want error")
	}
	_, err = Packages(0, 1<<62, 32)
	if err == nil {
		t.Error("Packages(0, 1<<62, 32) = nil error, want error")
	}
	_, err = Packages(0, 5, 0)
	if err == nil {
		t.Error("Packages(0, 5, 0) = nil error, want error")
	}
}

func TestEntryPackage(t *testing.T) {
	proof := []tlog.Hash{mustHash(t, "PlRNCrwHpqhGrupue0L7gxbjbMiKA9temvuZZDDpkaw=")}
	// EntryPackage carries the entries opaquely, so any bytes exercise it.
	entries := []byte("wire form entries")

	body, err := EntryPackage(entries, proof)
	if err != nil {
		t.Fatalf("EntryPackage: %s", err)
	}
	var expect cryptobyte.Builder
	expect.AddBytes(entries)
	expect.AddUint8(1)
	expect.AddBytes(proof[0][:])
	if !bytes.Equal(body, expect.BytesOrPanic()) {
		t.Errorf("EntryPackage = %x, want %x", body, expect.BytesOrPanic())
	}

	_, err = EntryPackage(nil, proof)
	if err == nil {
		t.Error("EntryPackage with no entries = nil error, want error")
	}
	_, err = EntryPackage(entries, make([]tlog.Hash, 64))
	if err == nil {
		t.Error("EntryPackage with 64 proof hashes = nil error, want error")
	}
}

func TestSignSubtreeRequest(t *testing.T) {
	hash := mustHash(t, "CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=")
	proof := []tlog.Hash{mustHash(t, "PlRNCrwHpqhGrupue0L7gxbjbMiKA9temvuZZDDpkaw=")}
	note := []byte("example.com/log\n512\n" + hash.String() + "\n\n— example.com/log AAAA\n")

	body, err := SignSubtreeRequest(256, 512, hash, proof, note)
	if err != nil {
		t.Fatalf("SignSubtreeRequest: %s", err)
	}
	expect := "subtree 256 512\n" + hash.String() + "\n" + proof[0].String() + "\n\n" + string(note)
	if string(body) != expect {
		t.Errorf("SignSubtreeRequest = %q, want %q", body, expect)
	}

	_, err = SignSubtreeRequest(-1, 512, hash, nil, note)
	if err == nil {
		t.Error("SignSubtreeRequest with a negative start = nil error, want error")
	}
	_, err = SignSubtreeRequest(512, 256, hash, nil, note)
	if err == nil {
		t.Error("SignSubtreeRequest with end before start = nil error, want error")
	}
	_, err = SignSubtreeRequest(512, 512, hash, nil, note)
	if err == nil {
		t.Error("SignSubtreeRequest with an empty subtree = nil error, want error")
	}
	_, err = SignSubtreeRequest(0, 512, hash, make([]tlog.Hash, 64), note)
	if err == nil {
		t.Error("SignSubtreeRequest with 64 proof lines = nil error, want error")
	}
	_, err = SignSubtreeRequest(0, 512, hash, nil, nil)
	if err == nil {
		t.Error("SignSubtreeRequest with an empty checkpoint = nil error, want error")
	}
}

func TestAddEntriesRequest(t *testing.T) {
	origin := "oid/1.3.6.1.4.1.44947.4.1.0.44"
	pkg := []byte{0, 1, 'x', 0}
	body, err := AddEntriesRequest(origin, 300, 700, []byte("ticket"), [][]byte{pkg})
	if err != nil {
		t.Fatalf("AddEntriesRequest: %s", err)
	}

	var expect cryptobyte.Builder
	expect.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes([]byte(origin))
	})
	expect.AddUint64(300)
	expect.AddUint64(700)
	expect.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes([]byte("ticket"))
	})
	expect.AddBytes(pkg)
	if !bytes.Equal(body, expect.BytesOrPanic()) {
		t.Errorf("AddEntriesRequest = %x, want %x", body, expect.BytesOrPanic())
	}

	_, err = AddEntriesRequest("", 0, 1, nil, nil)
	if err == nil {
		t.Error("AddEntriesRequest with an empty origin = nil error, want error")
	}
	_, err = AddEntriesRequest(origin, 2, 1, nil, nil)
	if err == nil {
		t.Error("AddEntriesRequest with an inverted interval = nil error, want error")
	}
	_, err = AddEntriesRequest(strings.Repeat("a", 0x10000), 0, 1, nil, nil)
	if err == nil {
		t.Error("AddEntriesRequest with an oversize origin = nil error, want error")
	}
	_, err = AddEntriesRequest(origin, 0, 1, make([]byte, 0x10000), nil)
	if err == nil {
		t.Error("AddEntriesRequest with an oversize ticket = nil error, want error")
	}
}
