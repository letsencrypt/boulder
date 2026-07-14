//go:build go1.27

package main

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/jmhodges/clock"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/trees/checkpoint"
	"github.com/letsencrypt/boulder/trees/cosignature"
	"github.com/letsencrypt/boulder/trees/mirror"
	"github.com/letsencrypt/boulder/trees/subtree"
	"github.com/letsencrypt/boulder/trees/tile"
)

const testOrigin = "example.com/log"
const testMirrorName = "mirror.test/m1"

// inmemReader is an in-memory tlog.HashReader indexed by stored hash index.
type inmemReader []tlog.Hash

func (m inmemReader) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, x := range indexes {
		out[i] = m[x]
	}
	return out, nil
}

// testLog plays the role of the upstream log: a growing RFC 6962 tree whose
// checkpoints it signs, and from which it builds consistency and subtree
// proofs.
type testLog struct {
	signer  note.Signer
	vkey    string
	reader  inmemReader
	entries [][]byte
}

func newTestLog(t *testing.T) *testLog {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, testOrigin)
	if err != nil {
		t.Fatalf("GenerateKey: %s", err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("NewSigner: %s", err)
	}
	return &testLog{signer: signer, vkey: vkey}
}

func (l *testLog) size() int64 { return int64(len(l.entries)) }

func (l *testLog) append(t *testing.T, n int) {
	t.Helper()
	for range n {
		entry := fmt.Appendf(nil, "entry-%d", len(l.entries))
		hashes, err := tlog.StoredHashes(int64(len(l.entries)), entry, l.reader)
		if err != nil {
			t.Fatalf("StoredHashes: %s", err)
		}
		l.reader = append(l.reader, hashes...)
		l.entries = append(l.entries, entry)
	}
}

// checkpoint returns the signed checkpoint note at the current size.
func (l *testLog) checkpoint(t *testing.T) []byte {
	t.Helper()
	root, err := tlog.TreeHash(l.size(), l.reader)
	if err != nil {
		t.Fatalf("TreeHash: %s", err)
	}
	c := checkpoint.Checkpoint{Origin: testOrigin, Tree: tlog.Tree{N: l.size(), Hash: root}}
	text, err := c.Marshal()
	if err != nil {
		t.Fatalf("marshaling checkpoint: %s", err)
	}
	signed, err := note.Sign(&note.Note{Text: text}, l.signer)
	if err != nil {
		t.Fatalf("note.Sign: %s", err)
	}
	return signed
}

func (l *testLog) consistencyProof(t *testing.T, oldSize int64) []tlog.Hash {
	t.Helper()
	if oldSize == 0 {
		return nil
	}
	proof, err := tlog.ProveTree(l.size(), oldSize, l.reader)
	if err != nil {
		t.Fatalf("ProveTree: %s", err)
	}
	return proof
}

// addEntriesBody builds an add-entries body for [uploadStart, uploadEnd),
// carrying the given number of canonical packages (use -1 for all).
func (l *testLog) addEntriesBody(t *testing.T, uploadStart, uploadEnd int64, packages int) []byte {
	t.Helper()
	all := mirror.EntryPackages(uploadStart, uploadEnd)
	if packages >= 0 && packages < len(all) {
		all = all[:packages]
	}
	var eps []mirror.EntryPackage
	for _, p := range all {
		entries := make([][]byte, 0, p.End-p.EntriesStart)
		for i := p.EntriesStart; i < p.End; i++ {
			entries = append(entries, l.entries[i])
		}
		proof, err := subtree.ConsistencyProof(p.SubtreeStart, p.End, uploadEnd, l.reader)
		if err != nil {
			t.Fatalf("SubtreeConsistencyProof(%d, %d, %d): %s", p.SubtreeStart, p.End, uploadEnd, err)
		}
		eps = append(eps, mirror.EntryPackage{Entries: entries, Proof: proof})
	}
	body, err := mirror.AddEntriesRequest{
		Origin:      testOrigin,
		UploadStart: uploadStart,
		UploadEnd:   uploadEnd,
		Packages:    eps,
	}.Marshal()
	if err != nil {
		t.Fatalf("Marshal add-entries: %s", err)
	}
	return body
}

func newTestServer(t *testing.T, vkey string) (*server, *cosignature.MLDSACosignatureVerifier, *httptest.Server) {
	t.Helper()
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	if err != nil {
		t.Fatalf("rand: %s", err)
	}
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
	if err != nil {
		t.Fatalf("NewPrivateKey: %s", err)
	}
	srv, err := newServer(config{
		StorageDir:    t.TempDir(),
		MirrorName:    testMirrorName,
		MirrorKeySeed: base64.StdEncoding.EncodeToString(seed),
		Logs:          []logConfig{{Origin: testOrigin, VerifierKey: vkey}},
	}, clock.New())
	if err != nil {
		t.Fatalf("newServer: %s", err)
	}
	verifier, err := cosignature.NewMLDSACosignatureVerifier(testMirrorName, key.PublicKey())
	if err != nil {
		t.Fatalf("NewMLDSACosignatureVerifier: %s", err)
	}
	ts := httptest.NewServer(srv.handler())
	t.Cleanup(ts.Close)
	return srv, verifier, ts
}

func post(t *testing.T, ts *httptest.Server, path string, body []byte) (int, []byte) {
	t.Helper()
	resp, err := http.Post(ts.URL+path, "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %s", path, err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response: %s", err)
	}
	return resp.StatusCode, got
}

func addCheckpointBody(t *testing.T, l *testLog, oldSize int64) []byte {
	t.Helper()
	body, err := mirror.AddCheckpointRequest{
		OldSize:    oldSize,
		Proof:      l.consistencyProof(t, oldSize),
		Checkpoint: l.checkpoint(t),
	}.Marshal()
	if err != nil {
		t.Fatalf("Marshal add-checkpoint: %s", err)
	}
	return body
}

// TestHashLeavesRFCVectors tests hashLeaves against the published RFC 6962
// reference roots for sizes 0-8.
func TestHashLeavesRFCVectors(t *testing.T) {
	entryHexes := []string{
		"",
		"00",
		"10",
		"2021",
		"3031",
		"40414243",
		"5051525354555657",
		"606162636465666768696a6b6c6d6e6f",
	}
	leaves := make([]tlog.Hash, len(entryHexes))
	for i, h := range entryHexes {
		entry, err := hex.DecodeString(h)
		if err != nil {
			t.Fatalf("decoding entry %q: %s", h, err)
		}
		leaves[i] = tlog.RecordHash(entry)
	}
	expect := []string{
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
		"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
		"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
		"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
		"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
		"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
		"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
		"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
	}
	for size := 0; size <= 8; size++ {
		got := mth(leaves[:size])
		if hex.EncodeToString(got[:]) != expect[size] {
			t.Errorf("hashLeaves(size %d) = %x, want %s", size, got, expect[size])
		}
	}
}

// validSubtree mirrors the MTC draft section 4.1 subtree definition, for
// enumerating the appendix C.1 vector: 0 <= start < end and start a multiple
// of BIT_CEIL(end-start).
func validSubtree(start, end int64) bool {
	if start < 0 || start >= end {
		return false
	}
	bitCeil := uint64(1) << bits.Len64(uint64(end-start-1))
	return uint64(start)&(bitCeil-1) == 0
}

// TestHashLeavesAppendixVector pins hashLeaves to the accumulated digest in
// the MTC draft appendix C.1 Subtree Hashes for every valid subtree up to size
// 130, which the draft's reference implementation also reproduces.
func TestHashLeavesAppendixVector(t *testing.T) {
	want := "94a95384a8c69acea9b50d035a58285b3a777cb7a724005faa5e1f1e1190007f"
	leaves := make([]tlog.Hash, 130)
	for i := range leaves {
		leaves[i] = tlog.RecordHash([]byte{byte(i)})
	}

	h := sha256.New()
	for end := int64(1); end <= 130; end++ {
		for start := int64(0); start < end; start++ {
			if !validSubtree(start, end) {
				continue
			}
			subtree := mth(leaves[start:end])
			fmt.Fprintf(h, "[%d, %d) %s\n", start, end, hex.EncodeToString(subtree[:]))
		}
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		t.Errorf("subtree hash accumulator:\n got  %s\n want %s", got, want)
	}
}

// TestMirrorRoundTrip drives the full submission flow over more than one tile
// width of entries (so the upload spans multiple packages with non-trivial
// subtree proofs), then verifies the returned and served mirror cosignatures.
func TestMirrorRoundTrip(t *testing.T) {
	l := newTestLog(t)
	l.append(t, 300)
	checkpoint := l.checkpoint(t)
	srv, v, ts := newTestServer(t, l.vkey)

	status, _ := post(t, ts, "/add-checkpoint", addCheckpointBody(t, l, 0))
	if status != http.StatusOK {
		t.Fatalf("add-checkpoint status = %d, want 200", status)
	}

	status, line := post(t, ts, "/add-entries", l.addEntriesBody(t, 0, 300, -1))
	if status != http.StatusOK {
		t.Fatalf("add-entries status = %d, want 200", status)
	}

	// The 200 body is the mirror's cosignature line; appended to the checkpoint
	// it forms a note the mirror verifier opens.
	cosigned := append(bytes.Clone(checkpoint), line...)
	n, err := note.Open(cosigned, note.VerifierList(v))
	if err != nil {
		t.Fatalf("note.Open of the cosigned checkpoint: %s", err)
	}
	_, ok := cosignature.Cosignature(n, v)
	if !ok {
		t.Error("mirror cosignature not present on the checkpoint")
	}

	// The served monitoring checkpoint carries the same cosignature.
	resp, err := http.Get(ts.URL + "/" + url.PathEscape(testOrigin) + "/checkpoint")
	if err != nil {
		t.Fatalf("GET checkpoint: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET checkpoint status = %d, want 200", resp.StatusCode)
	}
	served, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading served checkpoint: %s", err)
	}
	n, err = note.Open(served, note.VerifierList(v))
	if err != nil {
		t.Fatalf("note.Open of the served checkpoint: %s", err)
	}
	_, ok = cosignature.Cosignature(n, v)
	if !ok {
		t.Error("served checkpoint is not mirror-cosigned")
	}

	// Completing the upload prunes the pending checkpoint.
	ls := srv.logs[testOrigin]
	ls.mu.Lock()
	pending := len(ls.pending)
	ls.mu.Unlock()
	if pending != 0 {
		t.Errorf("pending checkpoints after completion = %d, want 0", pending)
	}
}

// TestRejectsOversizeBody pins the request body limit.
func TestRejectsOversizeBody(t *testing.T) {
	l := newTestLog(t)
	_, _, ts := newTestServer(t, l.vkey)
	status, _ := post(t, ts, "/add-checkpoint", make([]byte, maxAddCheckpointBody+1))
	if status != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize add-checkpoint status = %d, want 413", status)
	}
}

// TestMirrorResumption uploads the first package, expects a 202 advertising the
// next entry, then uploads the rest and expects a 200 cosignature.
func TestMirrorResumption(t *testing.T) {
	l := newTestLog(t)
	l.append(t, 300)
	_, v, ts := newTestServer(t, l.vkey)

	status, _ := post(t, ts, "/add-checkpoint", addCheckpointBody(t, l, 0))
	if status != http.StatusOK {
		t.Fatalf("add-checkpoint status = %d, want 200", status)
	}

	// Only the first canonical package: a complete prefix short of the upload
	// end.
	status, body := post(t, ts, "/add-entries", l.addEntriesBody(t, 0, 300, 1))
	if status != http.StatusAccepted {
		t.Fatalf("partial add-entries status = %d, want 202", status)
	}
	info, err := mirror.ParseMirrorInfo(body)
	if err != nil {
		t.Fatalf("ParseMirrorInfo: %s", err)
	}
	if info.NextEntry != tile.Width || info.TreeSize != 300 {
		t.Fatalf("mirror-info = {tree %d, next %d}, want {300, %d}", info.TreeSize, info.NextEntry, tile.Width)
	}

	// Resume from the advertised next entry.
	status, line := post(t, ts, "/add-entries", l.addEntriesBody(t, info.NextEntry, 300, -1))
	if status != http.StatusOK {
		t.Fatalf("resumed add-entries status = %d, want 200", status)
	}
	cosigned := append(bytes.Clone(l.checkpoint(t)), line...)
	n, err := note.Open(cosigned, note.VerifierList(v))
	if err != nil {
		t.Fatalf("note.Open: %s", err)
	}
	_, ok := cosignature.Cosignature(n, v)
	if !ok {
		t.Error("mirror cosignature missing after resumption")
	}
}

func TestAddCheckpointErrors(t *testing.T) {
	l := newTestLog(t)
	l.append(t, 8)
	_, _, ts := newTestServer(t, l.vkey)

	t.Run("Unknown origin", func(t *testing.T) {
		other := newTestLog(t)
		// Build a checkpoint for an origin the mirror does not know.
		emptyHash := mth(nil)
		c := checkpoint.Checkpoint{Origin: "other.example/log", Tree: tlog.Tree{N: 0, Hash: emptyHash}}
		text, err := c.Marshal()
		if err != nil {
			t.Fatalf("marshaling checkpoint: %s", err)
		}
		signed, err := note.Sign(&note.Note{Text: text}, other.signer)
		if err != nil {
			t.Fatalf("note.Sign: %s", err)
		}
		req, err := mirror.AddCheckpointRequest{OldSize: 0, Checkpoint: signed}.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %s", err)
		}
		status, _ := post(t, ts, "/add-checkpoint", req)
		if status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})

	t.Run("Wrong old size", func(t *testing.T) {
		// The mirror is at size 0, so an old size of 4 conflicts.
		body, err := mirror.AddCheckpointRequest{
			OldSize:    4,
			Proof:      l.consistencyProof(t, 4),
			Checkpoint: l.checkpoint(t),
		}.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %s", err)
		}
		status, resp := post(t, ts, "/add-checkpoint", body)
		if status != http.StatusConflict {
			t.Fatalf("status = %d, want 409", status)
		}
		size, err := mirror.ParseSize(resp)
		if err != nil || size != 0 {
			t.Errorf("conflict size body = (%d, %v), want (0, nil)", size, err)
		}
	})
}
