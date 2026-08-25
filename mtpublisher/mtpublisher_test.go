//go:build go1.27

package mtpublisher

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/bs3/bs3test"

	"github.com/letsencrypt/boulder/db"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/mtpublisher/mtpublishertest"
	"github.com/letsencrypt/boulder/privatekey"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test/vars"
	"github.com/letsencrypt/boulder/trees/checkpoint"
	"github.com/letsencrypt/boulder/trees/cosignature"
	"github.com/letsencrypt/boulder/trees/entry"
	"github.com/letsencrypt/boulder/trees/issuancelog"
	"github.com/letsencrypt/boulder/trees/pubkey"
	"github.com/letsencrypt/boulder/trees/tiles"
)

const (
	mtcLogID = "44947.4.1.0.44"
	mirrorID = "32473.9"
)

var testLogID = issuancelog.ID{CAID: "44947.4.1", LogNumber: 44}

func setupDB(t *testing.T) *db.WrappedMap {
	t.Helper()

	dbMap, err := sa.DBMapForTest(vars.DBConnMTCMeta_44947_4_1_0_44FullPerms)
	if err != nil {
		t.Fatalf("opening mtcmeta dbMap: %s", err)
	}
	truncate := func(ctx context.Context) error {
		_, err := dbMap.ExecContext(ctx, "TRUNCATE TABLE checkpoints")
		if err != nil {
			return err
		}
		_, err = dbMap.ExecContext(ctx, "TRUNCATE TABLE latestCheckpoint")
		return err
	}
	err = truncate(t.Context())
	if err != nil {
		t.Fatalf("truncating tables: %s", err)
	}
	t.Cleanup(func() {
		err := truncate(context.Background())
		if err != nil {
			t.Logf("cleaning up tables: %s", err)
		}
	})
	return dbMap
}

// setLatest points latestCheckpoint at the checkpoint with the given id, as the
// sequencer does when it adopts a checkpoint.
func setLatest(t *testing.T, dbMap *db.WrappedMap, logID string, id int64) {
	t.Helper()
	_, err := dbMap.ExecContext(t.Context(),
		"REPLACE INTO latestCheckpoint (mtcLogID, id) VALUES (?, ?)", logID, id)
	if err != nil {
		t.Fatalf("pointing latestCheckpoint at %d: %s", id, err)
	}
}

// testCAKey returns a deterministic ML-DSA-44 key standing in for the mtca's
// checkpoint signing key.
func testCAKey(t *testing.T) *mldsa.PrivateKey {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 101)
	}
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
	if err != nil {
		t.Fatalf("NewPrivateKey: %s", err)
	}
	return key
}

// caSignature returns the raw MTCA signature for a checkpoint of treeSize with
// a zero root hash, as insertCheckpoint stores.
func caSignature(t *testing.T, treeSize int64) []byte {
	t.Helper()
	ca, err := cosignature.NewCosigner(testLogID.CAID, testLogID.Origin(), privatekey.NewDeterministicSigner(testCAKey(t)))
	if err != nil {
		t.Fatalf("NewCosigner: %s", err)
	}
	timestamped, err := ca.CosignCheckpoint(tlog.Tree{N: treeSize})
	if err != nil {
		t.Fatalf("CosignCheckpoint: %s", err)
	}
	raw, err := cosignature.RawSignature(timestamped)
	if err != nil {
		t.Fatalf("RawSignature: %s", err)
	}
	return raw
}

func insertCheckpoint(t *testing.T, dbMap *db.WrappedMap, logID string, treeSize int64) int64 {
	t.Helper()

	res, err := dbMap.ExecContext(t.Context(),
		"INSERT INTO checkpoints (mtcLogID, mtcaSignature, treeSize, rootHash) VALUES (?, ?, ?, ?)",
		logID, caSignature(t, treeSize), treeSize, make([]byte, 32))
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

// testKey returns a deterministic ML-DSA-44 key so the test can verify the
// cosignatures the publisher stores.
func testKey(t *testing.T) *mldsa.PrivateKey {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
	if err != nil {
		t.Fatalf("NewPrivateKey: %s", err)
	}
	return key
}

// testMirror returns a LocalMirror that cosigns with key.
func testMirror(t *testing.T, key *mldsa.PrivateKey) *mtpublishertest.TestMirror {
	t.Helper()
	mirror, err := mtpublishertest.NewTestMirror(mirrorID, testLogID.Origin(), privatekey.NewDeterministicSigner(key))
	if err != nil {
		t.Fatalf("NewTestMirror: %s", err)
	}
	return mirror
}

func TestPublish(t *testing.T) {
	dbMap := setupDB(t)
	key := testKey(t)
	p, err := New(dbMap, time.Second, testLogID, testCAKey(t).PublicKey(), testMirror(t, key), blog.NewMock())
	if err != nil {
		t.Fatalf("New: %s", err)
	}

	// A pass over an empty table is a no-op.
	err = p.Publish(t.Context())
	if err != nil {
		t.Fatalf("p.Publish() on an empty table: %s", err)
	}

	// An older checkpoint that is not cosigned, which must be left untouched.
	olderCheckpointID := insertCheckpoint(t, dbMap, mtcLogID, 256)

	// The latest checkpoint, which we expect to be cosigned by p.Publish().
	latestCheckpointID := insertCheckpoint(t, dbMap, mtcLogID, 512)
	setLatest(t, dbMap, mtcLogID, latestCheckpointID)

	// A checkpoint for another log that was somehow inserted into this table,
	// which must be left untouched thanks to the mtcLogID guard.
	otherLogCheckpointID := insertCheckpoint(t, dbMap, "44947.4.2.0.99", 1024)

	// A precommitted checkpoint the CA has not signed yet, which must be left
	// untouched because latestCheckpoint does not reference it, even though its
	// tree is the largest.
	res, err := dbMap.ExecContext(t.Context(),
		"INSERT INTO checkpoints (mtcLogID, treeSize, rootHash) VALUES (?, ?, ?)",
		mtcLogID, int64(2048), make([]byte, 32))
	if err != nil {
		t.Fatalf("inserting precommitted checkpoint: %s", err)
	}
	precommitID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("reading insert id: %s", err)
	}

	err = p.Publish(t.Context())
	if err != nil {
		t.Fatalf("p.Publish(): %s", err)
	}

	type row struct {
		MirrorID  string `db:"mirrorID"`
		MirrorSig []byte `db:"mirrorSignature"`
	}
	var cosigned row
	err = dbMap.SelectOne(t.Context(), &cosigned, "SELECT mirrorID, mirrorSignature FROM checkpoints WHERE id = ?", latestCheckpointID)
	if err != nil {
		t.Fatalf("selecting the latest checkpoint: %s", err)
	}

	// Check that the latest checkpoint was cosigned, and the others were
	// untouched.
	if cosigned.MirrorID != mirrorID {
		t.Errorf("mirrorID = %q, want %q", cosigned.MirrorID, mirrorID)
	}
	if len(cosigned.MirrorSig) != mldsa.MLDSA44SignatureSize {
		t.Fatalf("latest checkpoint's mirrorSignature is %d bytes, want %d", len(cosigned.MirrorSig), mldsa.MLDSA44SignatureSize)
	}

	verifier, err := cosignature.NewVerifier(mirrorID, key.PublicKey())
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}
	text := "oid/1.3.6.1.4.1." + mtcLogID + "\n512\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
	timestampedSignature := append(make([]byte, 8), cosigned.MirrorSig...)
	if !verifier.Verify([]byte(text), timestampedSignature) {
		t.Error("stored mirror cosignature does not verify against the checkpoint text")
	}
	if !lacksCosignature(t, dbMap, olderCheckpointID) {
		t.Error("older checkpoint was cosigned, only the latest should be")
	}
	if !lacksCosignature(t, dbMap, otherLogCheckpointID) {
		t.Errorf("another log's checkpoint (id=%d) was cosigned, despite the mtcLogID guard", otherLogCheckpointID)
	}
	if !lacksCosignature(t, dbMap, precommitID) {
		t.Error("precommitted checkpoint was cosigned before the CA signed it")
	}
}

// TestPublishRejectsBadMTCASignature checks that a checkpoint whose stored
// MTCA signature does not verify is neither submitted nor cosigned.
func TestPublishRejectsBadMTCASignature(t *testing.T) {
	dbMap := setupDB(t)
	key := testKey(t)
	p, err := New(dbMap, time.Second, testLogID, testCAKey(t).PublicKey(), testMirror(t, key), blog.NewMock())
	if err != nil {
		t.Fatalf("New: %s", err)
	}

	// A well-formed MTCA signature over the wrong tree size.
	res, err := dbMap.ExecContext(t.Context(),
		"INSERT INTO checkpoints (mtcLogID, mtcaSignature, treeSize, rootHash) VALUES (?, ?, ?, ?)",
		mtcLogID, caSignature(t, 999), int64(512), make([]byte, 32))
	if err != nil {
		t.Fatalf("inserting checkpoint: %s", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("reading insert id: %s", err)
	}
	setLatest(t, dbMap, mtcLogID, id)

	err = p.Publish(t.Context())
	if err == nil {
		t.Error("publish with a bad MTCA signature = nil error, want error")
	}
	if !lacksCosignature(t, dbMap, id) {
		t.Error("cosignature was stored despite the MTCA signature failing verification")
	}
}

func TestPublishWhenLatestAlreadySigned(t *testing.T) {
	dbMap := setupDB(t)
	key := testKey(t)
	p, err := New(dbMap, time.Second, testLogID, testCAKey(t).PublicKey(), testMirror(t, key), blog.NewMock())
	if err != nil {
		t.Fatalf("New: %s", err)
	}

	// Insert a checkpoint that is already cosigned, which must be left
	// untouched.
	res, err := dbMap.ExecContext(t.Context(),
		"INSERT INTO checkpoints (mtcLogID, mtcaSignature, treeSize, rootHash, mirrorID, mirrorSignature) VALUES (?, ?, ?, ?, ?, ?)",
		mtcLogID, caSignature(t, 512), int64(512), make([]byte, 32), "existing.cosigner", []byte("already-signed-bruh"))
	if err != nil {
		t.Fatalf("inserting cosigned checkpoint: %s", err)
	}
	cosignedID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("reading insert id: %s", err)
	}
	setLatest(t, dbMap, mtcLogID, cosignedID)

	// Insert an older (non-latest) checkpoint that is not cosigned, which must
	// be left untouched.
	olderID := insertCheckpoint(t, dbMap, mtcLogID, 256)

	err = p.Publish(t.Context())
	if err != nil {
		t.Fatalf("p.Publish(): %s", err)
	}

	// The latest checkpoint is already cosigned, so the pass must leave both
	// checkpoints untouched.
	if !lacksCosignature(t, dbMap, olderID) {
		t.Error("older checkpoint was cosigned, the pass should have stopped at the signed latest")
	}
	var mirrorCosignature []byte
	err = dbMap.SelectOne(t.Context(), &mirrorCosignature, "SELECT mirrorSignature FROM checkpoints WHERE mtcLogID = ? AND treeSize = 512", mtcLogID)
	if err != nil {
		t.Fatalf("selecting the cosigned checkpoint: %s", err)
	}
	if string(mirrorCosignature) != "already-signed-bruh" {
		t.Errorf("existing cosignature was replaced: %q", mirrorCosignature)
	}
}

// sourceLog is a published source log in fake tile storage, with an earlier
// published tree so tests can exercise consistency proofs between the two.
type sourceLog struct {
	fs3        *bs3test.FakeS3
	older      tlog.Tree
	newer      tlog.Tree
	cp         *checkpoint.Checkpoint
	signedNote []byte

	// mirrorKey signs cosigLine, the mirror's signature line over the newer
	// tree, which carries the raw cosignature rawCosig.
	mirrorKey *mldsa.PrivateKey
	cosigLine []byte
	rawCosig  []byte
}

const testTilePrefix = "44947.4.1/44"

// newSourceLog publishes a 300 entry tree and grows it to 700 entries,
// returning the storage and the newer tree's checkpoint text.
func newSourceLog(t *testing.T) *sourceLog {
	t.Helper()
	fs3 := bs3test.New()
	f := &tiles.Frontier{}
	grow := func(n int64) tlog.Tree {
		t.Helper()
		for range n {
			err := f.AppendEntry(&entry.MTCLogEntry{}, &pubkey.MTCPublicKey{})
			if err != nil {
				t.Fatalf("AppendEntry: %s", err)
			}
		}
		err := f.Publish(t.Context(), fs3, testTilePrefix)
		if err != nil {
			t.Fatalf("Publish: %s", err)
		}
		return tlog.Tree{N: f.TreeSize(), Hash: f.RootHash()}
	}
	older := grow(300)
	newer := grow(400)
	cp := &checkpoint.Checkpoint{Origin: "oid/1.3.6.1.4.1." + mtcLogID, Tree: newer}

	caSeed := make([]byte, 32)
	for i := range caSeed {
		caSeed[i] = byte(i + 101)
	}
	caKey, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), caSeed)
	if err != nil {
		t.Fatalf("NewPrivateKey: %s", err)
	}
	ca, err := cosignature.NewCosigner(testLogID.CAID, testLogID.Origin(), privatekey.NewDeterministicSigner(caKey))
	if err != nil {
		t.Fatalf("NewCosigner: %s", err)
	}
	timestampedCA, err := ca.CosignCheckpoint(newer)
	if err != nil {
		t.Fatalf("CosignCheckpoint: %s", err)
	}
	rawCA, err := cosignature.RawSignature(timestampedCA)
	if err != nil {
		t.Fatalf("RawSignature: %s", err)
	}
	caVerifier, err := cosignature.NewVerifier(testLogID.CAID, caKey.PublicKey())
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}
	caLine, err := caVerifier.SignatureLine(cp.Origin, newer, rawCA)
	if err != nil {
		t.Fatalf("SignatureLine: %s", err)
	}
	signedNote, err := cp.SignedNoteForMirror(caLine)
	if err != nil {
		t.Fatalf("SignedNoteForMirror: %s", err)
	}

	mirrorSeed := make([]byte, 32)
	for i := range mirrorSeed {
		mirrorSeed[i] = byte(i + 201)
	}
	mirrorKey, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), mirrorSeed)
	if err != nil {
		t.Fatalf("NewPrivateKey: %s", err)
	}
	mirrorCosigner, err := cosignature.NewCosigner(mirrorID, cp.Origin, privatekey.NewDeterministicSigner(mirrorKey))
	if err != nil {
		t.Fatalf("NewCosigner: %s", err)
	}
	timestamped, err := mirrorCosigner.CosignCheckpoint(newer)
	if err != nil {
		t.Fatalf("CosignCheckpoint: %s", err)
	}
	rawCosig, err := cosignature.RawSignature(timestamped)
	if err != nil {
		t.Fatalf("RawSignature: %s", err)
	}
	mirrorVerifier, err := cosignature.NewVerifier(mirrorID, mirrorKey.PublicKey())
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}
	cosigLine, err := mirrorVerifier.SignatureLine(cp.Origin, newer, rawCosig)
	if err != nil {
		t.Fatalf("SignatureLine: %s", err)
	}
	return &sourceLog{
		fs3: fs3, older: older, newer: newer, cp: cp, signedNote: signedNote,
		mirrorKey: mirrorKey, cosigLine: cosigLine, rawCosig: rawCosig,
	}
}

// requestBody reads a request body, requiring gzip compression on add-entries
// requests.
func requestBody(t *testing.T, r *http.Request) []byte {
	t.Helper()
	if r.URL.Path == "/add-entries" && r.Header.Get("Content-Encoding") != "gzip" {
		t.Error("add-entries request is not gzip compressed")
	}
	reader := io.Reader(r.Body)
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Fatalf("opening request body: %s", err)
		}
		reader = zr
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("reading request body: %s", err)
	}
	return body
}

// parseUploadHeader pulls upload_start and the ticket out of an add-entries
// request body.
func parseUploadHeader(t *testing.T, body []byte) (int64, []byte) {
	t.Helper()
	originLen := int(binary.BigEndian.Uint16(body[:2]))
	rest := body[2+originLen:]
	uploadStart := int64(binary.BigEndian.Uint64(rest[:8]))
	ticketLen := int(binary.BigEndian.Uint16(rest[16:18]))
	return uploadStart, rest[18 : 18+ticketLen]
}

// TestMirrorCosign drives the client through a scripted exchange. The mirror
// answers the first add-checkpoint with "409 Conflict" at size 300 so the
// client must prove consistency from there, then answers the first add-entries
// with "202 Accepted" at entry 512 and a ticket the client must echo before the
// "200 Success" carrying the cosignature line, which the client presents at
// sign-subtree for the subtree signature over the whole tree.
func TestMirrorCosign(t *testing.T) {
	source := newSourceLog(t)
	line := string(source.cosigLine)

	var addCheckpointCalls, addEntriesCalls, signSubtreeCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := requestBody(t, r)
		switch r.URL.Path {
		case "/add-checkpoint":
			addCheckpointCalls++
			switch addCheckpointCalls {
			case 1:
				if !bytes.HasPrefix(body, []byte("old 0\n\n")) {
					t.Errorf("first add-checkpoint body %q does not claim old size 0 with an empty proof", body)
				}
				w.Header().Set("Content-Type", "text/x.tlog.size")
				w.WriteHeader(http.StatusConflict)
				io.WriteString(w, "300\n")
			default:
				header, _, ok := bytes.Cut(body, []byte("\n\n"))
				lines := strings.Split(string(header), "\n")
				if !ok || lines[0] != "old 300" {
					t.Fatalf("second add-checkpoint body %q does not claim old size 300", body)
				}
				proof := make(tlog.TreeProof, len(lines)-1)
				for i, l := range lines[1:] {
					h, err := tlog.ParseHash(l)
					if err != nil {
						t.Fatalf("proof line %q: %s", l, err)
					}
					proof[i] = h
				}
				err := tlog.CheckTree(proof, source.newer.N, source.newer.Hash, source.older.N, source.older.Hash)
				if err != nil {
					t.Errorf("client's consistency proof does not verify: %s", err)
				}
			}
		case "/add-entries":
			addEntriesCalls++
			uploadStart, ticket := parseUploadHeader(t, body)
			switch addEntriesCalls {
			case 1:
				if uploadStart != 0 || len(ticket) != 0 {
					t.Errorf("first add-entries upload_start = %d ticket = %q, want 0 and empty", uploadStart, ticket)
				}
				w.Header().Set("Content-Type", "text/x.tlog.mirror-info")
				w.WriteHeader(http.StatusAccepted)
				io.WriteString(w, "700\n512\n"+base64.StdEncoding.EncodeToString([]byte("resume"))+"\n")
			default:
				if uploadStart != 512 || string(ticket) != "resume" {
					t.Errorf("second add-entries upload_start = %d ticket = %q, want 512 and \"resume\"", uploadStart, ticket)
				}
				io.WriteString(w, line)
			}
		case "/sign-subtree":
			signSubtreeCalls++
			header, note, ok := bytes.Cut(body, []byte("\n\n"))
			expectHeader := fmt.Sprintf("subtree 0 %d\n%s", source.newer.N, source.newer.Hash)
			if !ok || string(header) != expectHeader {
				t.Errorf("sign-subtree header %q, want %q", header, expectHeader)
			}
			if !bytes.HasSuffix(note, source.cosigLine) {
				t.Errorf("sign-subtree note %q does not end with the add-entries cosignature line", note)
			}
			io.WriteString(w, line)
		default:
			t.Errorf("unexpected request to %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	m, err := NewMirrorClient(srv.URL, NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey())
	if err != nil {
		t.Fatalf("NewMirrorClient: %s", err)
	}
	got, err := m.Cosign(t.Context(), source.cp, source.signedNote)
	if err != nil {
		t.Fatalf("Cosign: %s", err)
	}
	if !bytes.Equal(got, source.rawCosig) {
		t.Errorf("Cosign = %x, want the mirror's raw cosignature %x", got, source.rawCosig)
	}
	if addCheckpointCalls != 2 || addEntriesCalls != 2 || signSubtreeCalls != 1 {
		t.Errorf("mirror saw %d add-checkpoint, %d add-entries, and %d sign-subtree calls, want 2, 2, and 1", addCheckpointCalls, addEntriesCalls, signSubtreeCalls)
	}
}

// TestMirrorCosignErrors covers the client's failure paths, with a mirror that
// refuses the checkpoint, a mirror demanding an upload_end the checkpoint
// cannot satisfy, and an unreachable mirror.
func TestMirrorCosignErrors(t *testing.T) {
	_, err := NewMirrorClient("", NewSource(nil, testTilePrefix), mirrorID, testKey(t).PublicKey())
	if err == nil {
		t.Error("NewMirrorClient with an empty base URL = nil error, want error")
	}

	source := newSourceLog(t)
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "checkpoint refused", http.StatusForbidden)
	}))
	defer refusing.Close()
	m, err := NewMirrorClient(refusing.URL, NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey())
	if err != nil {
		t.Fatalf("NewMirrorClient: %s", err)
	}
	_, err = m.Cosign(t.Context(), source.cp, source.signedNote)
	if err == nil {
		t.Fatal("Cosign against a refusing mirror = nil error, want error")
	}
	if !strings.Contains(err.Error(), "checkpoint refused") {
		t.Errorf("Cosign error %q does not carry the mirror's response", err)
	}

	mismatched := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/add-checkpoint" {
			return
		}
		w.Header().Set("Content-Type", "text/x.tlog.mirror-info")
		w.WriteHeader(http.StatusConflict)
		io.WriteString(w, "9000\n0\n\n")
	}))
	defer mismatched.Close()
	m, err = NewMirrorClient(mismatched.URL, NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey())
	if err != nil {
		t.Fatalf("NewMirrorClient: %s", err)
	}
	_, err = m.Cosign(t.Context(), source.cp, source.signedNote)
	if err == nil || !strings.Contains(err.Error(), "upload_end") {
		t.Errorf("Cosign against a mismatched mirror = %s, want an upload_end error", err)
	}

	unreachable, err := NewMirrorClient("http://127.0.0.1:1", NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey())
	if err != nil {
		t.Fatalf("NewMirrorClient: %s", err)
	}
	_, err = unreachable.Cosign(t.Context(), source.cp, source.signedNote)
	if err == nil {
		t.Error("Cosign against an unreachable mirror = nil error, want error")
	}

	// A mirror whose cosignature does not verify against the configured key.
	lying := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/add-checkpoint" {
			return
		}
		w.Write(source.cosigLine)
	}))
	defer lying.Close()
	m, err = NewMirrorClient(lying.URL, NewSource(source.fs3, testTilePrefix), mirrorID, testKey(t).PublicKey())
	if err != nil {
		t.Fatalf("NewMirrorClient: %s", err)
	}
	_, err = m.Cosign(t.Context(), source.cp, source.signedNote)
	if err == nil || !strings.Contains(err.Error(), "verification") {
		t.Errorf("Cosign with a mismatched key = %s, want a verification error", err)
	}
}
