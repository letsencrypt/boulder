//go:build go1.27

package mtpublisher

import (
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/db"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"
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

// checkpointBody is the canonical tlog-checkpoint note body for a tree.
func checkpointBody(tree tlog.Tree) string {
	return checkpoint.Checkpoint{Origin: testOrigin, Tree: tree}.String()
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
	signed, err := note.Sign(&note.Note{Text: checkpointBody(tree)}, signer)
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
	pendingBody []byte
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
		m.pendingBody = []byte(n.Text)
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
		line, err := m.cosigner.Cosign(m.pendingBody)
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

// newMirrorKey returns a fresh ML-DSA-44 cosigner and its public key.
func newMirrorKey(t *testing.T) (*cosignature.MLDSACosigner, *mldsa.PublicKey) {
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
	cosigner, err := cosignature.NewMLDSACosigner(mirrorName, key, clock.New())
	if err != nil {
		t.Fatalf("NewMLDSACosigner: %s", err)
	}
	return cosigner, key.PublicKey()
}

// startMirror writes a deterministic source log and stands up a thin
// real-crypto mirror for it, returning the MirrorConfig the publisher should
// use, the source log's backend, the source tree, and the mirror's public key
// for re-validation.
func startMirror(t *testing.T) (MirrorConfig, tilestore.Backend, tlog.Tree, *mldsa.PublicKey) {
	t.Helper()
	backend := fs.New(t.TempDir())
	tree, _, vkey, logVerifiers := synthSourceLog(t, backend, 300)
	cosigner, pub := newMirrorKey(t)
	srv := httptest.NewServer((&thinMirror{t: t, cosigner: cosigner, verifiers: logVerifiers}).handler())
	t.Cleanup(srv.Close)
	return MirrorConfig{
		BaseURL:           srv.URL,
		Name:              mirrorName,
		VerifierKey:       base64.StdEncoding.EncodeToString(pub.Bytes()),
		SourceOrigin:      testOrigin,
		SourceVerifierKey: vkey,
	}, backend, tree, pub
}

// validMirrorConfig returns a MirrorConfig with a real (throwaway) verifier
// key, for tests where the mirror is never actually contacted.
func validMirrorConfig(t *testing.T) MirrorConfig {
	t.Helper()
	_, pub := newMirrorKey(t)
	_, vkey, err := note.GenerateKey(rand.Reader, testOrigin)
	if err != nil {
		t.Fatalf("GenerateKey: %s", err)
	}
	return MirrorConfig{
		BaseURL:           "http://127.0.0.1:1",
		Name:              mirrorName,
		VerifierKey:       base64.StdEncoding.EncodeToString(pub.Bytes()),
		SourceOrigin:      testOrigin,
		SourceVerifierKey: vkey,
	}
}

// TestMirrorLog exercises the mirror handshake and cosignature validation
// directly, without the database: it mirrors a synthesized on-disk log to a
// real-crypto mirror and confirms the returned, validated cosignature verifies.
func TestMirrorLog(t *testing.T) {
	backend := fs.New(t.TempDir())
	tree, _, _, logVerifiers := synthSourceLog(t, backend, 300)
	src := tilestore.New(backend, testOrigin)

	cosigner, pub := newMirrorKey(t)
	verifier, err := cosignature.NewMLDSACosignatureVerifier(mirrorName, pub)
	if err != nil {
		t.Fatalf("NewMLDSACosignatureVerifier: %s", err)
	}
	srv := httptest.NewServer((&thinMirror{t: t, cosigner: cosigner, verifiers: logVerifiers}).handler())
	t.Cleanup(srv.Close)

	cosig, err := mirrorLog(t.Context(), srv.Client(), srv.URL, testOrigin, src, logVerifiers, verifier)
	if err != nil {
		t.Fatalf("mirrorLog: %s", err)
	}
	if !verifier.Verify([]byte(checkpointBody(tree)), cosig) {
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

	_, pub := newMirrorKey(t)
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
		{"Signed by the wrong key", checkpointBody(tree), otherSigner},
		{"Wrong origin", checkpoint.Checkpoint{Origin: "other.example/log", Tree: tree}.String(), signer},
		{"Stale tree size", checkpointBody(tlog.Tree{N: tree.N - 44, Hash: tree.Hash}), signer},
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
			_, err = mirrorLog(t.Context(), srv.Client(), srv.URL, testOrigin, src, logVerifiers, verifier)
			if err == nil {
				t.Error("mirrorLog = nil error, want error")
			}
		})
	}
}

// TestPublish covers the selection logic and the end-to-end cosignature: the
// publisher cosigns the latest uncosigned checkpoint for its log and leaves
// older checkpoints and other logs alone.
func TestPublish(t *testing.T) {
	dbMap := setupDB(t)
	mc, backend, tree, pub := startMirror(t)
	p, err := New(dbMap, time.Second, mtcLogID, mirrorID, mc, backend, clock.NewFake(), blog.NewMock())
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
	if !verifier.Verify([]byte(checkpointBody(tree)), row.MirrorSig) {
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
	mc, backend, tree, _ := startMirror(t)
	p, err := New(dbMap, time.Second, mtcLogID, mirrorID, mc, backend, clock.NewFake(), blog.NewMock())
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

// TestPublishWhenLatestAlreadySigned confirms an already-cosigned latest, and
// the older checkpoint behind it, are left untouched (the mirror is never
// contacted).
func TestPublishWhenLatestAlreadySigned(t *testing.T) {
	dbMap := setupDB(t)
	p, err := New(dbMap, time.Second, mtcLogID, mirrorID, validMirrorConfig(t), fs.New(t.TempDir()), clock.NewFake(), blog.NewMock())
	if err != nil {
		t.Fatalf("New: %s", err)
	}

	// A latest checkpoint that is already cosigned, which must be left
	// untouched.
	_, err = dbMap.ExecContext(t.Context(),
		"INSERT INTO checkpoints (mtcLogID, mtcaSignature, treeSize, rootHash, mirrorID, mirrorSignature) VALUES (?, ?, ?, ?, ?, ?)",
		mtcLogID, []byte("mtca-signature"), int64(512), make([]byte, 32), "existing.cosigner", []byte("already-signed-bruh"))
	if err != nil {
		t.Fatalf("inserting cosigned checkpoint: %s", err)
	}

	// An older uncosigned checkpoint, which must be left untouched.
	older := insertCheckpoint(t, dbMap, mtcLogID, 256, make([]byte, 32))

	err = p.publish(t.Context())
	if err != nil {
		t.Fatalf("publish: %s", err)
	}

	if !lacksCosignature(t, dbMap, older) {
		t.Error("older checkpoint was cosigned; the pass should stop at the signed latest")
	}
	var cosig []byte
	err = dbMap.SelectOne(t.Context(), &cosig, "SELECT mirrorSignature FROM checkpoints WHERE mtcLogID = ? AND treeSize = 512", mtcLogID)
	if err != nil {
		t.Fatalf("selecting the cosigned checkpoint: %s", err)
	}
	if string(cosig) != "already-signed-bruh" {
		t.Errorf("existing cosignature was replaced: %q", cosig)
	}
}
