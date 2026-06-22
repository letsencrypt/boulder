//go:build go1.27

package main

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
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
	body := checkpoint.Checkpoint{Origin: testOrigin, Tree: tlog.Tree{N: l.size(), Hash: root}}.String()
	signed, err := note.Sign(&note.Note{Text: body}, l.signer)
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

func newTestServer(t *testing.T, vkey string) (*cosignature.MLDSACosignatureVerifier, *httptest.Server) {
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
	return verifier, ts
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

// TestMirrorRoundTrip drives the full submission flow over more than one tile
// width of entries (so the upload spans multiple packages with non-trivial
// subtree proofs), then verifies the returned and served mirror cosignatures.
func TestMirrorRoundTrip(t *testing.T) {
	l := newTestLog(t)
	l.append(t, 300)
	checkpoint := l.checkpoint(t)
	v, ts := newTestServer(t, l.vkey)

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
}

// TestMirrorResumption uploads the first package, expects a 202 advertising the
// next entry, then uploads the rest and expects a 200 cosignature.
func TestMirrorResumption(t *testing.T) {
	l := newTestLog(t)
	l.append(t, 300)
	v, ts := newTestServer(t, l.vkey)

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
	_, ts := newTestServer(t, l.vkey)

	t.Run("Unknown origin", func(t *testing.T) {
		other := newTestLog(t)
		// Build a checkpoint for an origin the mirror does not know.
		emptyHash := subtree.Hash(nil)
		body := checkpoint.Checkpoint{Origin: "other.example/log", Tree: tlog.Tree{N: 0, Hash: emptyHash}}.String()
		signed, err := note.Sign(&note.Note{Text: body}, other.signer)
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
