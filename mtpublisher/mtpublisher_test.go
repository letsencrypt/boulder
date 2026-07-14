//go:build go1.27

package mtpublisher

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/db"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
	"github.com/letsencrypt/boulder/trees/checkpoint"
	"github.com/letsencrypt/boulder/trees/cosignature"
	"github.com/letsencrypt/boulder/trees/mirror"
	"github.com/letsencrypt/boulder/trees/tilestore"
	"github.com/letsencrypt/boulder/trees/tilestore/fs"
)

const (
	mtcLogID   = "44947.4.1.0.44"
	mirrorID   = "32473.9"
	testOrigin = "example.com/log"
	mirrorName = "mirror.test/m1"
)

func setupDB(t *testing.T) *db.WrappedMap {
	t.Helper()

	// These tests need the MTC meta database, which only runs in the Boulder
	// test harness (which sets BOULDER_CONFIG_DIR). Skip a bare local run
	// rather than failing on a connection error.
	if os.Getenv("BOULDER_CONFIG_DIR") == "" {
		t.Skip("requires the MTC meta DB; run via the Boulder test harness")
	}

	dbMap, err := sa.DBMapForTest(vars.DBConnMTCMeta_44947_4_1_0_44FullPerms)
	if err != nil {
		t.Fatalf("opening mtcmeta dbMap: %s", err)
	}
	_, err = dbMap.ExecContext(t.Context(), "TRUNCATE TABLE checkpoints")
	if err != nil {
		t.Fatalf("truncating checkpoints: %s", err)
	}
	t.Cleanup(func() {
		_, err := dbMap.ExecContext(context.Background(), "TRUNCATE TABLE checkpoints")
		if err != nil {
			t.Logf("cleaning up checkpoints: %s", err)
		}
	})
	return dbMap
}

func insertCheckpoint(t *testing.T, dbMap *db.WrappedMap, logID string, treeSize int64, rootHash []byte) int64 {
	t.Helper()

	res, err := dbMap.ExecContext(t.Context(),
		"INSERT INTO checkpoints (mtcLogID, mtcaSignature, treeSize, rootHash) VALUES (?, ?, ?, ?)",
		logID, []byte("mtca-signature"), treeSize, rootHash)
	if err != nil {
		t.Fatalf("inserting checkpoint (%s size %d): %s", logID, treeSize, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("reading insert id: %s", err)
	}
	return id
}

func lacksCosignature(t *testing.T, dbMap *db.WrappedMap, id int64) bool {
	t.Helper()
	var count int64
	err := dbMap.SelectOne(t.Context(), &count,
		"SELECT COUNT(*) FROM checkpoints WHERE id = ? AND mirrorID IS NULL AND mirrorSignature IS NULL", id)
	if err != nil {
		t.Fatalf("querying checkpoint %d: %s", id, err)
	}
	return count == 1
}

// checkpointText is the canonical tlog-checkpoint note text for origin and
// tree.
func checkpointText(t *testing.T, origin string, tree tlog.Tree) string {
	t.Helper()
	c := checkpoint.Checkpoint{Origin: origin, Tree: tree}
	text, err := c.Marshal()
	if err != nil {
		t.Fatalf("marshaling checkpoint: %s", err)
	}
	return text
}

// synthSourceLog writes n entries and a log-signed checkpoint into a tilestore
// over backend, the way the publisher reads its source log. It returns the
// resulting tree, the log's signer, its verifier key, and its note verifiers.
func synthSourceLog(t *testing.T, backend tilestore.Backend, n int) (tlog.Tree, note.Signer, string, note.Verifiers) {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, testOrigin)
	if err != nil {
		t.Fatalf("GenerateKey: %s", err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("NewSigner: %s", err)
	}
	verifier, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}

	src := tilestore.New(backend, testOrigin)
	entries := make([][]byte, n)
	for i := range entries {
		entries[i] = fmt.Appendf(nil, "entry-%d", i)
	}
	tree, err := src.Append(t.Context(), 0, entries)
	if err != nil {
		t.Fatalf("Append: %s", err)
	}
	signed, err := note.Sign(&note.Note{Text: checkpointText(t, testOrigin, tree)}, signer)
	if err != nil {
		t.Fatalf("note.Sign: %s", err)
	}
	err = src.WriteCheckpoint(t.Context(), signed)
	if err != nil {
		t.Fatalf("WriteCheckpoint: %s", err)
	}
	return tree, signer, vkey, note.VerifierList(verifier)
}

// thinMirror is a minimal real-crypto tlog-mirror: it verifies the submitted
// checkpoint with the real checkpoint package and, once the upload reaches the
// checkpoint size, returns a real ML-DSA-44 cosignature. It skips the entry
// verification the full test-srv does (covered by that server's own tests);
// here it exists to feed the publisher a genuine cosignature to validate.
type thinMirror struct {
	t         *testing.T
	cosigner  *cosignature.MLDSACosigner
	verifiers note.Verifiers

	mu          sync.Mutex
	pendingText []byte
	pendingSize int64
}

func (m *thinMirror) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /add-checkpoint", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "reading body", http.StatusBadRequest)
			return
		}
		req, err := mirror.ParseAddCheckpointRequest(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cp, n, err := checkpoint.Open(req.Checkpoint, m.verifiers)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		m.mu.Lock()
		m.pendingText = []byte(n.Text)
		m.pendingSize = cp.Tree.N
		m.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /add-entries", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "reading body", http.StatusBadRequest)
			return
		}
		req, _, err := mirror.ParseAddEntriesRequest(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if req.UploadEnd != m.pendingSize {
			http.Error(w, "test mirror expects a single full upload", http.StatusInternalServerError)
			return
		}
		line, err := m.cosigner.Cosign(m.pendingText)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, err = io.WriteString(w, line)
		if err != nil {
			m.t.Errorf("writing cosignature response: %s", err)
		}
	})
	return mux
}

// newMirrorKey returns a fresh ML-DSA-44 cosigner signing as name, and its
// public key.
func newMirrorKey(t *testing.T, name string) (*cosignature.MLDSACosigner, *mldsa.PublicKey) {
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
	cosigner, err := cosignature.NewMLDSACosigner(name, key, clock.New())
	if err != nil {
		t.Fatalf("NewMLDSACosigner: %s", err)
	}
	return cosigner, key.PublicKey()
}

// newThinMirror stands up a thinMirror with a fresh cosigner key and returns
// the publisher-side config for it and the cosigner's public key.
func newThinMirror(t *testing.T, logVerifiers note.Verifiers, id, name string, tier1 bool) (MirrorConfig, *mldsa.PublicKey) {
	t.Helper()
	cosigner, pub := newMirrorKey(t, name)
	srv := httptest.NewServer((&thinMirror{t: t, cosigner: cosigner, verifiers: logVerifiers}).handler())
	t.Cleanup(srv.Close)
	return MirrorConfig{
		ID:          id,
		BaseURL:     srv.URL,
		Name:        name,
		VerifierKey: base64.StdEncoding.EncodeToString(pub.Bytes()),
		Tier1:       tier1,
	}, pub
}

// startMirror writes a deterministic source log of n entries and stands up a
// thin real-crypto tier-1 mirror for it, returning the source and mirror
// configs the publisher should use, the source backend and tree, and the
// mirror's public key for re-validation.
func startMirror(t *testing.T, n int) (SourceConfig, MirrorConfig, tilestore.Backend, tlog.Tree, *mldsa.PublicKey) {
	t.Helper()
	backend := fs.New(t.TempDir())
	tree, _, vkey, logVerifiers := synthSourceLog(t, backend, n)
	mc, pub := newThinMirror(t, logVerifiers, mirrorID, mirrorName, true)
	return SourceConfig{Origin: testOrigin, VerifierKey: vkey}, mc, backend, tree, pub
}

// validConfigs returns a SourceConfig and a tier-1 MirrorConfig with real
// (throwaway) keys, for tests where the mirror is never actually contacted.
func validConfigs(t *testing.T) (SourceConfig, MirrorConfig) {
	t.Helper()
	_, pub := newMirrorKey(t, mirrorName)
	_, vkey, err := note.GenerateKey(rand.Reader, testOrigin)
	if err != nil {
		t.Fatalf("GenerateKey: %s", err)
	}
	return SourceConfig{Origin: testOrigin, VerifierKey: vkey}, MirrorConfig{
		ID:          mirrorID,
		BaseURL:     "http://127.0.0.1:1",
		Name:        mirrorName,
		VerifierKey: base64.StdEncoding.EncodeToString(pub.Bytes()),
		Tier1:       true,
	}
}

// TestMirrorLog exercises the mirror handshake and cosignature validation
// directly, without the database: it mirrors a synthesized on-disk log to a
// real-crypto mirror and confirms the returned, validated cosignature verifies.
func TestMirrorLog(t *testing.T) {
	backend := fs.New(t.TempDir())
	tree, _, _, logVerifiers := synthSourceLog(t, backend, 300)
	src := tilestore.New(backend, testOrigin)

	cosigner, pub := newMirrorKey(t, mirrorName)
	verifier, err := cosignature.NewMLDSACosignatureVerifier(mirrorName, pub)
	if err != nil {
		t.Fatalf("NewMLDSACosignatureVerifier: %s", err)
	}
	srv := httptest.NewServer((&thinMirror{t: t, cosigner: cosigner, verifiers: logVerifiers}).handler())
	t.Cleanup(srv.Close)

	cosig, err := mirrorLog(t.Context(), srv.Client(), srv.URL, testOrigin, src, logVerifiers, verifier, &bodyMemo{})
	if err != nil {
		t.Fatalf("mirrorLog: %s", err)
	}
	if !verifier.Verify([]byte(checkpointText(t, testOrigin, tree)), cosig) {
		t.Error("cosignature returned by mirrorLog does not verify against the checkpoint")
	}
}

// TestMirrorLogRejectsBadSourceCheckpoint confirms mirrorLog refuses, before
// ever contacting the mirror, a source checkpoint that does not verify, names
// the wrong origin, or does not describe the source tree.
func TestMirrorLogRejectsBadSourceCheckpoint(t *testing.T) {
	backend := fs.New(t.TempDir())
	tree, signer, _, logVerifiers := synthSourceLog(t, backend, 300)
	src := tilestore.New(backend, testOrigin)

	_, pub := newMirrorKey(t, mirrorName)
	verifier, err := cosignature.NewMLDSACosignatureVerifier(mirrorName, pub)
	if err != nil {
		t.Fatalf("NewMLDSACosignatureVerifier: %s", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("mirror contacted (%s) despite a bad source checkpoint", r.URL.Path)
		http.Error(w, "unexpected request", http.StatusTeapot)
	}))
	t.Cleanup(srv.Close)

	otherSkey, _, err := note.GenerateKey(rand.Reader, testOrigin)
	if err != nil {
		t.Fatalf("GenerateKey: %s", err)
	}
	otherSigner, err := note.NewSigner(otherSkey)
	if err != nil {
		t.Fatalf("NewSigner: %s", err)
	}

	cases := []struct {
		name   string
		body   string
		signer note.Signer
	}{
		{"Signed by the wrong key", checkpointText(t, testOrigin, tree), otherSigner},
		{"Wrong origin", checkpointText(t, "other.example/log", tree), signer},
		{"Stale tree size", checkpointText(t, testOrigin, tlog.Tree{N: tree.N - 44, Hash: tree.Hash}), signer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signed, err := note.Sign(&note.Note{Text: tc.body}, tc.signer)
			if err != nil {
				t.Fatalf("note.Sign: %s", err)
			}
			err = src.WriteCheckpoint(t.Context(), signed)
			if err != nil {
				t.Fatalf("WriteCheckpoint: %s", err)
			}
			_, err = mirrorLog(t.Context(), srv.Client(), srv.URL, testOrigin, src, logVerifiers, verifier, &bodyMemo{})
			if err == nil {
				t.Error("mirrorLog = nil error, want error")
			}
		})
	}
}

// TestQuorumGatesRecording covers the tier and quorum logic with three
// mirrors: two tier-1 commits are required before the cosignature is
// recorded, and a tier-2 commit never counts.
func TestQuorumGatesRecording(t *testing.T) {
	dbMap := setupDB(t)
	backend := fs.New(t.TempDir())
	tree, _, vkey, logVerifiers := synthSourceLog(t, backend, 300)
	source := SourceConfig{Origin: testOrigin, VerifierKey: vkey}

	m1, _ := newThinMirror(t, logVerifiers, "32473.9", "mirror.test/m1", true)
	m2, pub2 := newThinMirror(t, logVerifiers, "32473.10", "mirror.test/m2", true)
	m3, _ := newThinMirror(t, logVerifiers, "32473.11", "mirror.test/m3", false)

	p, err := New(dbMap, time.Second, mtcLogID, source, []MirrorConfig{m1, m2, m3}, 2, backend, metrics.NoopRegisterer, clock.NewFake(), blog.NewMock())
	if err != nil {
		t.Fatalf("New: %s", err)
	}
	id := insertCheckpoint(t, dbMap, mtcLogID, tree.N, tree.Hash[:])

	// One tier-1 commit and one tier-2 commit do not meet the quorum of 2.
	err = p.publishMirror(t.Context(), p.mirrors[0])
	if err != nil {
		t.Fatalf("publishMirror(m1): %s", err)
	}
	err = p.publishMirror(t.Context(), p.mirrors[2])
	if err != nil {
		t.Fatalf("publishMirror(m3): %s", err)
	}
	if !lacksCosignature(t, dbMap, id) {
		t.Fatal("cosignature recorded before the tier-1 quorum was met")
	}
	// The gauge counts only the tier-1 commit, not the tier-2 one.
	test.AssertMetricWithLabelsEquals(t, p.tier1Committed, prometheus.Labels{}, 1)

	// The second tier-1 commit completes the quorum, and its cosignature is
	// the one recorded.
	err = p.publishMirror(t.Context(), p.mirrors[1])
	if err != nil {
		t.Fatalf("publishMirror(m2): %s", err)
	}
	var row struct {
		MirrorID  string `db:"mirrorID"`
		MirrorSig []byte `db:"mirrorSignature"`
	}
	err = dbMap.SelectOne(t.Context(), &row, "SELECT mirrorID, mirrorSignature FROM checkpoints WHERE id = ?", id)
	if err != nil {
		t.Fatalf("selecting the checkpoint: %s", err)
	}
	if row.MirrorID != "32473.10" {
		t.Errorf("mirrorID = %q, want the quorum-completing mirror %q", row.MirrorID, "32473.10")
	}
	test.AssertMetricWithLabelsEquals(t, p.tier1Committed, prometheus.Labels{}, 2)
	verifier, err := cosignature.NewMLDSACosignatureVerifier("mirror.test/m2", pub2)
	if err != nil {
		t.Fatalf("NewMLDSACosignatureVerifier: %s", err)
	}
	if !verifier.Verify([]byte(checkpointText(t, testOrigin, tree)), row.MirrorSig) {
		t.Error("recorded cosignature does not verify against the checkpoint")
	}
}

// TestNewRejectsBadMirrorSet covers the mirror-set and quorum validation.
func TestNewRejectsBadMirrorSet(t *testing.T) {
	source, mc := validConfigs(t)
	tier2 := mc
	tier2.ID = "32473.10"
	tier2.Tier1 = false

	cases := []struct {
		name    string
		mirrors []MirrorConfig
		quorum  int
	}{
		{"No mirrors", nil, 1},
		{"Zero quorum", []MirrorConfig{mc}, 0},
		{"Quorum above the tier-1 count", []MirrorConfig{mc, tier2}, 2},
		{"Duplicate mirror ID", []MirrorConfig{mc, mc}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(nil, time.Second, mtcLogID, source, tc.mirrors, tc.quorum, fs.New(t.TempDir()), metrics.NoopRegisterer, clock.NewFake(), blog.NewMock())
			if err == nil {
				t.Error("New = nil error, want error")
			}
		})
	}
}

// chunkedMirror is a thin mirror that tracks its ingested size across
// requests, issues a resumption ticket with each mirror-info response, and
// requires the next request to echo it. Like thinMirror it skips entry
// verification, which the full test-srv covers.
type chunkedMirror struct {
	t         *testing.T
	cosigner  *cosignature.MLDSACosigner
	verifiers note.Verifiers

	mu          sync.Mutex
	pendingText []byte
	pendingSize int64
	size        int64
	ticket      []byte
	addEntries  int
}

func (m *chunkedMirror) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /add-checkpoint", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "reading body", http.StatusBadRequest)
			return
		}
		req, err := mirror.ParseAddCheckpointRequest(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cp, n, err := checkpoint.Open(req.Checkpoint, m.verifiers)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		m.mu.Lock()
		m.pendingText = []byte(n.Text)
		m.pendingSize = cp.Tree.N
		m.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /add-entries", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "reading body", http.StatusBadRequest)
			return
		}
		req, _, err := mirror.ParseAddEntriesRequest(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		m.addEntries++
		if len(req.Packages) > maxUploadPackages {
			m.t.Errorf("request %d carries %d packages, more than the %d cap", m.addEntries, len(req.Packages), maxUploadPackages)
		}
		if !bytes.Equal(req.Ticket, m.ticket) {
			m.t.Errorf("request %d ticket = %q, want %q", m.addEntries, req.Ticket, m.ticket)
		}
		if req.UploadStart != m.size {
			http.Error(w, "unexpected upload start", http.StatusConflict)
			return
		}
		for _, pkg := range req.Packages {
			m.size += int64(len(pkg.Entries))
		}
		if m.size < m.pendingSize {
			m.ticket = fmt.Appendf(nil, "ticket-at-%d", m.size)
			info := mirror.Info{TreeSize: m.pendingSize, NextEntry: m.size, Ticket: m.ticket}
			b, err := info.Marshal()
			if err != nil {
				http.Error(w, "marshaling mirror-info", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", mirror.ContentTypeMirrorInfo)
			w.WriteHeader(http.StatusAccepted)
			_, err = w.Write(b)
			if err != nil {
				m.t.Errorf("writing mirror-info response: %s", err)
			}
			return
		}
		line, err := m.cosigner.Cosign(m.pendingText)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, err = io.WriteString(w, line)
		if err != nil {
			m.t.Errorf("writing cosignature response: %s", err)
		}
	})
	return mux
}

// TestMirrorLogChunksAndEchoesTicket uploads a log large enough to exceed the
// per-request package cap and confirms mirrorLog resumes with the mirror's
// resumption ticket until the upload completes.
func TestMirrorLogChunksAndEchoesTicket(t *testing.T) {
	backend := fs.New(t.TempDir())
	// More entries than maxUploadPackages full packages hold, forcing a
	// second request.
	n := maxUploadPackages*256 + 200
	tree, _, _, logVerifiers := synthSourceLog(t, backend, n)
	src := tilestore.New(backend, testOrigin)

	cosigner, pub := newMirrorKey(t, mirrorName)
	verifier, err := cosignature.NewMLDSACosignatureVerifier(mirrorName, pub)
	if err != nil {
		t.Fatalf("NewMLDSACosignatureVerifier: %s", err)
	}
	cm := &chunkedMirror{t: t, cosigner: cosigner, verifiers: logVerifiers}
	srv := httptest.NewServer(cm.handler())
	t.Cleanup(srv.Close)

	cosig, err := mirrorLog(t.Context(), srv.Client(), srv.URL, testOrigin, src, logVerifiers, verifier, &bodyMemo{})
	if err != nil {
		t.Fatalf("mirrorLog: %s", err)
	}
	if !verifier.Verify([]byte(checkpointText(t, testOrigin, tree)), cosig) {
		t.Error("cosignature does not verify against the checkpoint")
	}
	if cm.addEntries != 2 {
		t.Errorf("add-entries requests = %d, want 2", cm.addEntries)
	}
}

// bundleCountingBackend counts Gets of entry bundle objects.
type bundleCountingBackend struct {
	inner tilestore.Backend

	mu   sync.Mutex
	gets int
}

func (c *bundleCountingBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if strings.Contains(key, "/tile/entries/") {
		c.mu.Lock()
		c.gets++
		c.mu.Unlock()
	}
	return c.inner.Get(ctx, key)
}

func (c *bundleCountingBackend) Put(ctx context.Context, key string, data []byte) error {
	return c.inner.Put(ctx, key, data)
}

func (c *bundleCountingBackend) bundleGets() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gets
}

// TestBodyMemoSharesBundleReads confirms that when two mirrors upload the same
// interval through a shared bodyMemo, only the first upload reads entry
// bundles from the backend.
func TestBodyMemoSharesBundleReads(t *testing.T) {
	counting := &bundleCountingBackend{inner: fs.New(t.TempDir())}
	tree, _, _, logVerifiers := synthSourceLog(t, counting, 300)
	src := tilestore.New(counting, testOrigin)

	memo := &bodyMemo{}
	var afterFirst int
	for i, name := range []string{"mirror.test/m1", "mirror.test/m2"} {
		cosigner, pub := newMirrorKey(t, name)
		verifier, err := cosignature.NewMLDSACosignatureVerifier(name, pub)
		if err != nil {
			t.Fatalf("NewMLDSACosignatureVerifier: %s", err)
		}
		srv := httptest.NewServer((&thinMirror{t: t, cosigner: cosigner, verifiers: logVerifiers}).handler())
		t.Cleanup(srv.Close)

		cosig, err := mirrorLog(t.Context(), srv.Client(), srv.URL, testOrigin, src, logVerifiers, verifier, memo)
		if err != nil {
			t.Fatalf("mirrorLog to %s: %s", name, err)
		}
		if !verifier.Verify([]byte(checkpointText(t, testOrigin, tree)), cosig) {
			t.Errorf("cosignature from %s does not verify against the checkpoint", name)
		}
		if i == 0 {
			afterFirst = counting.bundleGets()
			if afterFirst == 0 {
				t.Fatal("first mirror upload read no entry bundles")
			}
		}
	}
	if got := counting.bundleGets(); got != afterFirst {
		t.Errorf("second mirror upload read %d entry bundles, want 0: the memo should have served its body", got-afterFirst)
	}
}

// TestPublish covers the selection logic and the end-to-end cosignature: the
// publisher cosigns the latest uncosigned checkpoint for its log and leaves
// older checkpoints and other logs alone.
func TestPublish(t *testing.T) {
	dbMap := setupDB(t)
	source, mc, backend, tree, pub := startMirror(t, 300)
	p, err := New(dbMap, time.Second, mtcLogID, source, []MirrorConfig{mc}, 1, backend, metrics.NoopRegisterer, clock.NewFake(), blog.NewMock())
	if err != nil {
		t.Fatalf("New: %s", err)
	}

	// An empty table is a no-op.
	err = p.publish(t.Context())
	if err != nil {
		t.Fatalf("publish on an empty table: %s", err)
	}

	zero := make([]byte, 32)
	// An older uncosigned checkpoint, which must be left untouched.
	older := insertCheckpoint(t, dbMap, mtcLogID, 256, zero)
	// The latest checkpoint, matching the source log, which we expect cosigned.
	latest := insertCheckpoint(t, dbMap, mtcLogID, tree.N, tree.Hash[:])
	// A checkpoint for another log, left untouched by the mtcLogID guard.
	other := insertCheckpoint(t, dbMap, "44947.4.2.0.99", 1024, zero)

	err = p.publish(t.Context())
	if err != nil {
		t.Fatalf("publish: %s", err)
	}

	var row struct {
		MirrorID  string `db:"mirrorID"`
		MirrorSig []byte `db:"mirrorSignature"`
	}
	err = dbMap.SelectOne(t.Context(), &row, "SELECT mirrorID, mirrorSignature FROM checkpoints WHERE id = ?", latest)
	if err != nil {
		t.Fatalf("selecting the latest checkpoint: %s", err)
	}
	if row.MirrorID != mirrorID {
		t.Errorf("mirrorID = %q, want %q", row.MirrorID, mirrorID)
	}
	// The recorded signature must be a valid mirror cosignature over the
	// checkpoint.
	verifier, err := cosignature.NewMLDSACosignatureVerifier(mirrorName, pub)
	if err != nil {
		t.Fatalf("NewMLDSACosignatureVerifier: %s", err)
	}
	if !verifier.Verify([]byte(checkpointText(t, testOrigin, tree)), row.MirrorSig) {
		t.Error("recorded cosignature does not verify against the checkpoint")
	}

	if !lacksCosignature(t, dbMap, older) {
		t.Error("older checkpoint was cosigned, only the latest should be")
	}
	if !lacksCosignature(t, dbMap, other) {
		t.Errorf("other-log checkpoint (id=%d) was cosigned despite the mtcLogID guard", other)
	}
}

// TestPublishRejectsMismatchedCheckpoint confirms the publisher refuses to
// cosign when the latest checkpoint does not match the source log it would
// mirror, rather than recording a cosignature over a different tree.
func TestPublishRejectsMismatchedCheckpoint(t *testing.T) {
	dbMap := setupDB(t)
	source, mc, backend, tree, _ := startMirror(t, 300)
	p, err := New(dbMap, time.Second, mtcLogID, source, []MirrorConfig{mc}, 1, backend, metrics.NoopRegisterer, clock.NewFake(), blog.NewMock())
	if err != nil {
		t.Fatalf("New: %s", err)
	}

	// A latest checkpoint whose size does not match the source log.
	id := insertCheckpoint(t, dbMap, mtcLogID, tree.N+1, tree.Hash[:])
	err = p.publish(t.Context())
	if err == nil {
		t.Fatal("publish accepted a checkpoint that does not match the source log")
	}
	if !lacksCosignature(t, dbMap, id) {
		t.Error("mismatched checkpoint was cosigned")
	}
}

// TestPublishWhenLatestAlreadySigned confirms an already-cosigned latest keeps
// its cosignature and the older checkpoint behind it stays untouched, while
// the mirror is still brought up to date with the latest tree.
func TestPublishWhenLatestAlreadySigned(t *testing.T) {
	dbMap := setupDB(t)
	source, mc, backend, tree, _ := startMirror(t, 512)
	p, err := New(dbMap, time.Second, mtcLogID, source, []MirrorConfig{mc}, 1, backend, metrics.NoopRegisterer, clock.NewFake(), blog.NewMock())
	if err != nil {
		t.Fatalf("New: %s", err)
	}

	// A latest checkpoint that is already cosigned, which must keep its
	// existing cosignature.
	_, err = dbMap.ExecContext(t.Context(),
		"INSERT INTO checkpoints (mtcLogID, mtcaSignature, treeSize, rootHash, mirrorID, mirrorSignature) VALUES (?, ?, ?, ?, ?, ?)",
		mtcLogID, []byte("mtca-signature"), tree.N, tree.Hash[:], "existing.cosigner", []byte("already-signed-bruh"))
	if err != nil {
		t.Fatalf("inserting cosigned checkpoint: %s", err)
	}

	// An older uncosigned checkpoint, which must be left untouched.
	older := insertCheckpoint(t, dbMap, mtcLogID, 256, make([]byte, 32))

	err = p.publish(t.Context())
	if err != nil {
		t.Fatalf("publish: %s", err)
	}

	if p.mirrors[0].committedSize != tree.N {
		t.Errorf("mirror committed size = %d, want %d: the mirror must be kept up to date regardless", p.mirrors[0].committedSize, tree.N)
	}
	if !lacksCosignature(t, dbMap, older) {
		t.Error("older checkpoint was cosigned; the pass should only target the latest")
	}
	var cosig []byte
	err = dbMap.SelectOne(t.Context(), &cosig, "SELECT mirrorSignature FROM checkpoints WHERE mtcLogID = ? AND treeSize = ?", mtcLogID, tree.N)
	if err != nil {
		t.Fatalf("selecting the cosigned checkpoint: %s", err)
	}
	if string(cosig) != "already-signed-bruh" {
		t.Errorf("existing cosignature was replaced: %q", cosig)
	}
}
