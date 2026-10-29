package mtpublisher

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/bs3/bs3test"
	"github.com/letsencrypt/boulder/core/reloid"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/mtpublisher/mtpublishertest"
	"github.com/letsencrypt/boulder/must"
	"github.com/letsencrypt/boulder/privatekey"
	"github.com/letsencrypt/boulder/trees/checkpoint"
	"github.com/letsencrypt/boulder/trees/cosignature"
	"github.com/letsencrypt/boulder/trees/cosigned"
	"github.com/letsencrypt/boulder/trees/entry"
	"github.com/letsencrypt/boulder/trees/issuancelog"
	"github.com/letsencrypt/boulder/trees/mirror"
	"github.com/letsencrypt/boulder/trees/pubkey"
	"github.com/letsencrypt/boulder/trees/subtree"
	"github.com/letsencrypt/boulder/trees/tiles"
	"github.com/letsencrypt/boulder/trees/treedb"
)

const (
	mtcLogID = "44947.4.1.0.44"
	mirrorID = "32473.9"
)

var (
	testLogID = must.Do(issuancelog.Config{CAID: "44947.4.1", LogNumber: 44}.Load())
	mirrorOID = must.Do(reloid.FromString(mirrorID))
)

// fakeCheckpointDB holds the latest checkpoint of one log and its subtrees, or
// none for a log that is not initialized, and stores the mirror cosignatures
// on them. The mtca tests truncate the mtcmeta database and run in parallel
// with these, so they cannot share it.
type fakeCheckpointDB struct {
	latest   *treedb.CheckpointModel
	subtrees []*treedb.CheckpointSubtreeModel
}

func (f *fakeCheckpointDB) LatestCheckpoint(_ context.Context, mtcLogID string) (*treedb.CheckpointModel, error) {
	if f.latest == nil || f.latest.MTCLogID != mtcLogID {
		return nil, treedb.ErrIssuanceLogNotInitialized
	}
	return f.latest, nil
}

func (f *fakeCheckpointDB) AddMirrorSignature(_ context.Context, id int64, mirrorID string, mirrorSignature []byte, mtcLogID string) error {
	if f.latest == nil || id != f.latest.ID || mtcLogID != f.latest.MTCLogID {
		return fmt.Errorf("adding mirror signature: checkpoint %d for %s not found", id, mtcLogID)
	}
	f.latest.MirrorID = &mirrorID
	f.latest.MirrorSignature = mirrorSignature
	return nil
}

func (f *fakeCheckpointDB) GetUnsignedSubtrees(_ context.Context, mtcLogID string, maxEnd uint64, limit int) ([]*treedb.CheckpointSubtreeModel, error) {
	var unsigned []*treedb.CheckpointSubtreeModel
	for _, subtree := range slices.Backward(f.subtrees) {
		if len(unsigned) == limit {
			break
		}
		if subtree.MTCLogID == mtcLogID && subtree.MirrorID == nil && subtree.SubtreeEnd <= maxEnd {
			unsigned = append(unsigned, subtree)
		}
	}
	return unsigned, nil
}

func (f *fakeCheckpointDB) AddSubtreeMirrorSignature(_ context.Context, id int64, mirrorID string, mirrorSignature []byte, mtcLogID string) error {
	for _, subtree := range f.subtrees {
		if subtree.ID == id && subtree.MTCLogID == mtcLogID {
			subtree.MirrorID = &mirrorID
			subtree.MirrorSignature = mirrorSignature
			return nil
		}
	}
	return fmt.Errorf("adding mirror signature: subtree %d for %s not found", id, mtcLogID)
}

// testPublisher returns a publisher over checkpoints whose mirror cosigns with
// key.
func testPublisher(t *testing.T, key *mldsa.PrivateKey, checkpoints *fakeCheckpointDB) *mtpublisher {
	t.Helper()
	p, err := New(checkpoints, time.Second, testLogID, testCAVerifier(t), testMirror(t, key), blog.NewMock())
	if err != nil {
		t.Fatalf("New: %s", err)
	}
	return p
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

// testCAVerifier returns a verifier for testCAKey.
func testCAVerifier(t *testing.T) *cosignature.Verifier {
	t.Helper()
	v, err := cosignature.NewVerifier(testLogID.CAID(), testCAKey(t).PublicKey())
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}
	return v
}

// caSignature returns the raw MTCA signature for a checkpoint of treeSize with
// a zero root hash, as testCheckpoint holds.
func caSignature(t *testing.T, treeSize int64) []byte {
	t.Helper()
	ca, err := cosignature.NewCosigner(testLogID.CAID(), testLogID.Origin(), privatekey.NewDeterministicSigner(testCAKey(t)))
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

// testCheckpoint returns a checkpoint of 512 entries with a zero root hash,
// signed by the MTCA and awaiting the mirror cosignature, and the subtree
// [0, 512) it covers.
func testCheckpoint(t *testing.T) (*treedb.CheckpointModel, *treedb.CheckpointSubtreeModel) {
	t.Helper()
	return testCheckpointAt(t, 1, 512), &treedb.CheckpointSubtreeModel{
		ID:            7,
		MTCLogID:      mtcLogID,
		MTCASignature: caSignature(t, 512),
		SubtreeStart:  0,
		SubtreeEnd:    512,
		SubtreeHash:   make([]byte, 32),
	}
}

// testCheckpointAt returns a checkpoint of the test log at treeSize with a
// valid MTCA signature and no mirror cosignature.
func testCheckpointAt(t *testing.T, id, treeSize int64) *treedb.CheckpointModel {
	t.Helper()
	return &treedb.CheckpointModel{
		ID:            id,
		MTCLogID:      mtcLogID,
		MTCASignature: caSignature(t, treeSize),
		TreeSize:      treeSize,
		RootHash:      make([]byte, 32),
	}
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

// testMirror returns a TestMirror that cosigns with key.
func testMirror(t *testing.T, key *mldsa.PrivateKey) *mtpublishertest.TestMirror {
	t.Helper()
	mirror, err := mtpublishertest.NewTestMirror(mirrorID, testLogID.Origin(), privatekey.NewDeterministicSigner(key))
	if err != nil {
		t.Fatalf("NewTestMirror: %s", err)
	}
	return mirror
}

func TestPublish(t *testing.T) {
	key := testKey(t)
	checkpoints := &fakeCheckpointDB{}
	p := testPublisher(t, key, checkpoints)

	// A pass over a log that is not initialized is a no-op.
	err := p.PublishCheckpoint(t.Context())
	if err != nil {
		t.Fatalf("p.PublishCheckpoint() on a log that is not initialized: %s", err)
	}

	// The latest checkpoint, which we expect to be cosigned by p.Publish().
	latest, subtree := testCheckpoint(t)
	checkpoints.latest = latest
	checkpoints.subtrees = []*treedb.CheckpointSubtreeModel{subtree}

	err = p.PublishCheckpoint(t.Context())
	if err != nil {
		t.Fatalf("p.PublishCheckpoint(): %s", err)
	}
	err = p.CosignSubtrees(t.Context())
	if err != nil {
		t.Fatalf("p.CosignSubtrees(): %s", err)
	}

	if latest.MirrorID == nil {
		t.Fatal("latest checkpoint was not cosigned")
	}
	if *latest.MirrorID != mirrorID {
		t.Errorf("mirrorID = %q, want %q", *latest.MirrorID, mirrorID)
	}

	verifier, err := cosignature.NewVerifier(mirrorOID, key.PublicKey())
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}
	text := "oid/1.3.6.1.4.1." + mtcLogID + "\n512\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
	_, _, err = checkpoint.Open([]byte(text+"\n"+string(latest.MirrorSignature)), verifier)
	if err != nil {
		t.Errorf("stored mirror cosignature does not verify against the checkpoint text: %s", err)
	}

	if subtree.MirrorID == nil {
		t.Fatal("subtree was not cosigned")
	}
	if *subtree.MirrorID != mirrorID {
		t.Errorf("subtree mirrorID = %q, want %q", *subtree.MirrorID, mirrorID)
	}
	if !verifier.VerifySubtreeSignature(testLogID.Origin(), 0, 512, tlog.Hash(subtree.SubtreeHash), subtree.MirrorSignature) {
		t.Error("stored subtree signature does not verify")
	}
}

// TestPublishRejectsBadMTCASignature checks that a checkpoint or subtree whose
// stored MTCA signature does not verify is neither submitted nor cosigned.
func TestPublishRejectsBadMTCASignature(t *testing.T) {
	latest, subtree := testCheckpoint(t)
	checkpoints := &fakeCheckpointDB{latest: latest, subtrees: []*treedb.CheckpointSubtreeModel{subtree}}
	p := testPublisher(t, testKey(t), checkpoints)
	err := p.PublishCheckpoint(t.Context())
	if err != nil {
		t.Fatalf("p.PublishCheckpoint(): %s", err)
	}

	// The next checkpoint carries a well-formed MTCA signature over the wrong
	// tree size.
	next := testCheckpointAt(t, 2, 1024)
	next.MTCASignature = caSignature(t, 999)
	checkpoints.latest = next
	err = p.PublishCheckpoint(t.Context())
	if err == nil {
		t.Error("publish with a bad MTCA signature = nil error, want error")
	}
	if next.MirrorID != nil || next.MirrorSignature != nil {
		t.Error("cosignature was stored despite the MTCA signature failing verification")
	}

	// The rejected checkpoint does not hold back the subtrees the mirror's
	// checkpoint includes.
	err = p.CosignSubtrees(t.Context())
	if err != nil {
		t.Fatalf("p.CosignSubtrees(): %s", err)
	}
	if !subtree.Mirrored() {
		t.Error("subtree was not cosigned after the checkpoint was rejected")
	}

	latest, subtree = testCheckpoint(t)
	subtree.MTCASignature = caSignature(t, 999)
	p = testPublisher(t, testKey(t), &fakeCheckpointDB{latest: latest, subtrees: []*treedb.CheckpointSubtreeModel{subtree}})
	err = p.PublishCheckpoint(t.Context())
	if err != nil {
		t.Fatalf("p.PublishCheckpoint(): %s", err)
	}
	err = p.CosignSubtrees(t.Context())
	if err == nil {
		t.Error("cosigning a subtree with a bad MTCA signature = nil error, want error")
	}
	if subtree.Mirrored() {
		t.Error("subtree signature was stored despite the MTCA signature failing verification")
	}
}

// TestCosignSubtreesWithinMirrorCheckpoint checks that a pass signs every
// subtree the mirror's checkpoint includes and leaves those beyond it for a
// later pass.
func TestCosignSubtreesWithinMirrorCheckpoint(t *testing.T) {
	_, subtree := testCheckpoint(t)
	subtrees := []*treedb.CheckpointSubtreeModel{subtree}
	for i, end := range []uint64{256, 1024, 2048} {
		subtrees = append(subtrees, &treedb.CheckpointSubtreeModel{
			ID:            subtree.ID + int64(i) + 1,
			MTCLogID:      mtcLogID,
			MTCASignature: caSignature(t, int64(end)), //nolint:gosec // G115: the ends above fit.
			SubtreeEnd:    end,
			SubtreeHash:   make([]byte, 32),
		})
	}
	checkpoints := &fakeCheckpointDB{latest: testCheckpointAt(t, 2, 1024), subtrees: subtrees}
	p := testPublisher(t, testKey(t), checkpoints)
	err := p.PublishCheckpoint(t.Context())
	if err != nil {
		t.Fatalf("p.PublishCheckpoint(): %s", err)
	}

	// The mirror is at 1024, so the pass signs [0, 1024), [0, 512), and
	// [0, 256), and leaves [0, 2048).
	err = p.CosignSubtrees(t.Context())
	if err != nil {
		t.Fatalf("p.CosignSubtrees(): %s", err)
	}
	for _, s := range subtrees[:3] {
		if !s.Mirrored() {
			t.Errorf("subtree [0, %d) within the mirror's checkpoint was not cosigned", s.SubtreeEnd)
		}
	}
	if subtrees[3].Mirrored() {
		t.Error("subtree beyond the mirror's checkpoint was cosigned")
	}

	// Once the mirror is at 2048, the next pass signs [0, 2048).
	checkpoints.latest = testCheckpointAt(t, 3, 2048)
	err = p.PublishCheckpoint(t.Context())
	if err != nil {
		t.Fatalf("p.PublishCheckpoint(): %s", err)
	}
	err = p.CosignSubtrees(t.Context())
	if err != nil {
		t.Fatalf("p.CosignSubtrees(): %s", err)
	}
	if !subtrees[3].Mirrored() {
		t.Error("subtree within the mirror's new checkpoint was not cosigned")
	}
}

// TestPublishMirrorError checks that a failed cosigning stores nothing.
func TestPublishMirrorError(t *testing.T) {
	latest, subtree := testCheckpoint(t)
	p := testPublisher(t, testKey(t), &fakeCheckpointDB{latest: latest, subtrees: []*treedb.CheckpointSubtreeModel{subtree}})
	otherLogMirror, err := mtpublishertest.NewTestMirror(mirrorID, "oid/1.3.6.1.4.1.44947.4.2.0.99", privatekey.NewDeterministicSigner(testKey(t)))
	if err != nil {
		t.Fatalf("NewTestMirror: %s", err)
	}
	p.mirror = otherLogMirror

	err = p.PublishCheckpoint(t.Context())
	if err == nil {
		t.Error("publish with a mirror refusing the checkpoint = nil error, want error")
	}
	if latest.MirrorID != nil || latest.MirrorSignature != nil {
		t.Error("cosignature was stored despite the mirror refusing the checkpoint")
	}

	err = p.CosignSubtrees(t.Context())
	if err == nil {
		t.Error("cosigning subtrees with a mirror refusing them = nil error, want error")
	}
	if subtree.Mirrored() {
		t.Error("subtree signature was stored despite the mirror refusing it")
	}
}

func TestPublishWhenLatestAlreadySigned(t *testing.T) {
	// The latest checkpoint is already cosigned, which must be left untouched.
	existingMirrorID := "existing.cosigner"
	latest, _ := testCheckpoint(t)
	latest.MirrorID = &existingMirrorID
	latest.MirrorSignature = []byte("already-signed-bruh")
	p := testPublisher(t, testKey(t), &fakeCheckpointDB{latest: latest})

	err := p.PublishCheckpoint(t.Context())
	if err != nil {
		t.Fatalf("p.PublishCheckpoint(): %s", err)
	}

	if string(latest.MirrorSignature) != "already-signed-bruh" {
		t.Errorf("existing cosignature was replaced: %q", latest.MirrorSignature)
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
	ca         *cosignature.Cosigner

	// mirror cosigns with mirrorKey. The lines are its checkpoint and subtree
	// cosignatures over the newer tree, the latter carrying subtreeSignature.
	mirrorKey                 *mldsa.PrivateKey
	mirror                    *mtpublishertest.TestMirror
	checkpointCosignatureLine []byte
	subtreeCosignatureLine    []byte
	subtreeSignature          []byte
}

const testTilePrefix = "44947.4.1/44"

// serveMirrorCheckpoint serves the newer tree's checkpoint with the mirror's
// cosignature at the path c2sp.org/tlog-mirror puts it.
func (s *sourceLog) serveMirrorCheckpoint(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	expectPath := fmt.Sprintf("/%x/checkpoint", sha256.Sum256([]byte(s.cp.Origin)))
	if r.URL.Path != expectPath {
		t.Errorf("GET %s, want %s", r.URL.Path, expectPath)
		http.NotFound(w, r)
		return
	}
	w.Write(append(slices.Clone(s.signedNote), s.checkpointCosignatureLine...))
	w.Write(greaseLine)
}

// greaseLine is a signature line by an unknown key, which some logs and mirrors
// add to their checkpoints so that clients ignore unknown keys.
var greaseLine = []byte("— grease.invalid " + base64.StdEncoding.EncodeToString(make([]byte, 4+8+mldsa.MLDSA44SignatureSize)) + "\n")

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
	ca, err := cosignature.NewCosigner(testLogID.CAID(), testLogID.Origin(), privatekey.NewDeterministicSigner(caKey))
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
	caLine, err := ca.SignatureLine(0, rawCA)
	if err != nil {
		t.Fatalf("SignatureLine: %s", err)
	}
	signedNote, err := cp.SignedNote(caLine)
	if err != nil {
		t.Fatalf("SignedNote: %s", err)
	}

	mirrorSeed := make([]byte, 32)
	for i := range mirrorSeed {
		mirrorSeed[i] = byte(i + 201)
	}
	mirrorKey, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), mirrorSeed)
	if err != nil {
		t.Fatalf("NewPrivateKey: %s", err)
	}
	mirror, err := mtpublishertest.NewTestMirror(mirrorID, cp.Origin, privatekey.NewDeterministicSigner(mirrorKey))
	if err != nil {
		t.Fatalf("NewTestMirror: %s", err)
	}
	mirrorVerifier, err := cosignature.NewVerifier(mirrorOID, mirrorKey.PublicKey())
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}
	// A witness cosigns its checkpoint at the current time, which the
	// TestMirror cannot, so the line is signed by hand.
	message, err := (&cosigned.Message{
		CosignerName: mirrorVerifier.Name(),
		Timestamp:    1_700_000_000,
		LogOrigin:    cp.Origin,
		Start:        0,
		End:          uint64(newer.N), //nolint:gosec // G115: the tree has 700 entries
		SubtreeHash:  newer.Hash,
	}).Marshal()
	if err != nil {
		t.Fatalf("Marshal: %s", err)
	}
	checkpointSignature, err := mirrorKey.Sign(nil, message, nil)
	if err != nil {
		t.Fatalf("Sign: %s", err)
	}
	checkpointCosignatureLine, err := cosignature.SignatureLine(mirrorVerifier.Name(), mirrorVerifier.KeyHash(), 1_700_000_000, checkpointSignature)
	if err != nil {
		t.Fatalf("SignatureLine: %s", err)
	}
	_, err = mirror.SubmitCheckpoint(t.Context(), cp, signedNote)
	if err != nil {
		t.Fatalf("SubmitCheckpoint: %s", err)
	}
	subtreeSignature, err := mirror.CosignSubtree(t.Context(), cp, checkpointCosignatureLine, 0, cp.Tree.N, cp.Tree.Hash)
	if err != nil {
		t.Fatalf("CosignSubtree: %s", err)
	}
	subtreeCosignatureLine, err := cosignature.SignatureLine(mirrorVerifier.Name(), mirrorVerifier.KeyHash(), 0, subtreeSignature)
	if err != nil {
		t.Fatalf("SignatureLine: %s", err)
	}
	return &sourceLog{
		fs3: fs3, older: older, newer: newer, cp: cp, signedNote: signedNote, ca: ca,
		mirrorKey: mirrorKey, mirror: mirror, checkpointCosignatureLine: checkpointCosignatureLine, subtreeCosignatureLine: subtreeCosignatureLine, subtreeSignature: subtreeSignature,
	}
}

// signSubtreeServer serves the newer tree's checkpoint and answers sign-subtree
// for the subtree [start, end) with hash subtreeHash with signature, after checking
// the request's proof against the newer tree.
func (s *sourceLog) signSubtreeServer(t *testing.T, start, end int64, subtreeHash tlog.Hash, signature []byte) *httptest.Server {
	t.Helper()
	referenceCheckpoint, err := s.cp.SignedNote(s.checkpointCosignatureLine)
	if err != nil {
		t.Fatalf("SignedNote: %s", err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			s.serveMirrorCheckpoint(t, w, r)
			return
		}
		if r.URL.Path != "/sign-subtree" {
			t.Errorf("unexpected request to %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		header, note, ok := bytes.Cut(requestBody(t, r), []byte("\n\n"))
		if !ok || !bytes.Equal(note, referenceCheckpoint) {
			t.Errorf("sign-subtree note %q, want the mirror's checkpoint with its line alone %q", note, referenceCheckpoint)
		}
		lines := strings.Split(string(header), "\n")
		expectHeader := fmt.Sprintf("subtree %d %d\n%s", start, end, subtreeHash)
		if len(lines) < 2 || strings.Join(lines[:2], "\n") != expectHeader {
			t.Errorf("sign-subtree header %q does not begin with %q", header, expectHeader)
			http.Error(w, "bad subtree", http.StatusBadRequest)
			return
		}
		proof := make([]tlog.Hash, len(lines)-2)
		for i, l := range lines[2:] {
			h, err := tlog.ParseHash(l)
			if err != nil {
				t.Errorf("proof line %q: %s", l, err)
				http.Error(w, "bad proof line", http.StatusBadRequest)
				return
			}
			proof[i] = h
		}
		if !subtree.VerifyConsistency(start, end, s.newer.N, proof, subtreeHash, s.newer.Hash) {
			t.Errorf("client's subtree proof for [%d, %d) does not verify against the tree of size %d", start, end, s.newer.N)
			http.Error(w, "bad proof", http.StatusBadRequest)
			return
		}
		w.Write([]byte(base64.StdEncoding.EncodeToString(signature) + "\n"))
	}))
}

// TestMirrorCosignPartialSubtree checks that a subtree that does not start at
// 0 is proven against the mirror's checkpoint and its signature verified over
// that subtree.
func TestMirrorCosignPartialSubtree(t *testing.T) {
	source := newSourceLog(t)
	indexes := make([]int64, 0, 128)
	for i := range int64(128) {
		indexes = append(indexes, tlog.StoredHashIndex(0, 256+i))
	}
	leaves, err := tlog.TileHashReader(source.newer, tiles.NewTileReader(t.Context(), source.fs3, testTilePrefix)).ReadHashes(indexes)
	if err != nil {
		t.Fatalf("reading leaf hashes: %s", err)
	}
	partialHash := subtree.MTH(leaves)
	partialSignature, err := source.mirror.CosignSubtree(t.Context(), source.cp, source.checkpointCosignatureLine, 256, 384, partialHash)
	if err != nil {
		t.Fatalf("CosignSubtree: %s", err)
	}
	srv := source.signSubtreeServer(t, 256, 384, partialHash, partialSignature)
	defer srv.Close()

	m, err := NewMirrorClient(srv.URL, srv.URL, NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey(), 10*time.Second)
	if err != nil {
		t.Fatalf("NewMirrorClient: %s", err)
	}
	mirrored, mirrorLine, err := m.LatestCheckpoint(t.Context(), source.cp.Origin)
	if err != nil {
		t.Fatalf("LatestCheckpoint: %s", err)
	}
	subtreeSignature, err := m.CosignSubtree(t.Context(), mirrored, mirrorLine, 256, 384, partialHash)
	if err != nil {
		t.Fatalf("CosignSubtree: %s", err)
	}
	if !bytes.Equal(subtreeSignature, partialSignature) {
		t.Errorf("CosignSubtree = %x, want the mirror's %x", subtreeSignature, partialSignature)
	}
}

// TestSourceEntryPackage checks the first package of an upload that does not
// begin on a package boundary: it must carry only the entries from
// EntriesStart, with a subtree consistency proof for the whole package subtree
// from SubtreeStart.
func TestSourceEntryPackage(t *testing.T) {
	source := newSourceLog(t)
	packages, err := mirror.Packages(300, source.newer.N, mirror.MaxPackagesPerRequest)
	if err != nil {
		t.Fatalf("Packages: %s", err)
	}
	p := packages[0]
	if p.EntriesStart == p.SubtreeStart {
		t.Fatalf("Packages(300, %d)[0] = %+v, want a package carrying entries from past its subtree start", source.newer.N, p)
	}

	body, err := NewSource(source.fs3, testTilePrefix).entryPackage(t.Context(), source.newer, p)
	if err != nil {
		t.Fatalf("entryPackage: %s", err)
	}
	rest := cryptobyte.String(body)
	var entries []cryptobyte.String
	for range p.End - p.EntriesStart {
		var e cryptobyte.String
		if !rest.ReadUint16LengthPrefixed(&e) {
			t.Fatalf("entry package holds fewer than %d entries", p.End-p.EntriesStart)
		}
		entries = append(entries, e)
	}
	var numHashes uint8
	if !rest.ReadUint8(&numHashes) {
		t.Fatal("entry package ends before num_hashes")
	}
	proof := make([]tlog.Hash, numHashes)
	for i := range proof {
		if !rest.CopyBytes(proof[i][:]) {
			t.Fatalf("entry package ends inside proof hash %d", i)
		}
	}
	if !rest.Empty() {
		t.Errorf("entry package has %d trailing bytes", len(rest))
	}

	indexes := make([]int64, 0, p.End-p.SubtreeStart)
	for i := p.SubtreeStart; i < p.End; i++ {
		indexes = append(indexes, tlog.StoredHashIndex(0, i))
	}
	reader := tlog.TileHashReader(source.newer, tiles.NewTileReader(t.Context(), source.fs3, testTilePrefix))
	leaves, err := reader.ReadHashes(indexes)
	if err != nil {
		t.Fatalf("reading leaf hashes: %s", err)
	}
	for i, e := range entries {
		if tlog.RecordHash(e) != leaves[p.EntriesStart-p.SubtreeStart+int64(i)] {
			t.Errorf("entry %d of the package does not hash to leaf %d", i, p.EntriesStart+int64(i))
		}
	}
	if !subtree.VerifyConsistency(p.SubtreeStart, p.End, source.newer.N, proof, subtree.MTH(leaves), source.newer.Hash) {
		t.Errorf("subtree consistency proof for [%d, %d) does not verify against the tree of size %d", p.SubtreeStart, p.End, source.newer.N)
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
			t.Errorf("opening request body: %s", err)
			return nil
		}
		reader = zr
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Errorf("reading request body: %s", err)
		return nil
	}
	return body
}

// parseUploadHeader pulls upload_start and the ticket out of an add-entries
// request body.
func parseUploadHeader(t *testing.T, body []byte) (int64, []byte) {
	t.Helper()
	originLen := int(body[0])
	rest := body[1+originLen:]
	uploadStart := int64(binary.BigEndian.Uint64(rest[:8])) //nolint:gosec // G115: the client writes upload_start from an int64 entry index.
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

	var addCheckpointCalls, addEntriesCalls, signSubtreeCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			source.serveMirrorCheckpoint(t, w, r)
			return
		}
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
				fmt.Fprint(w, "300\n")
			default:
				header, _, ok := bytes.Cut(body, []byte("\n\n"))
				lines := strings.Split(string(header), "\n")
				if !ok || lines[0] != "old 300" {
					t.Errorf("second add-checkpoint body %q does not claim old size 300", body)
					http.Error(w, "bad old size", http.StatusBadRequest)
					return
				}
				proof := make(tlog.TreeProof, len(lines)-1)
				for i, l := range lines[1:] {
					h, err := tlog.ParseHash(l)
					if err != nil {
						t.Errorf("proof line %q: %s", l, err)
						http.Error(w, "bad proof line", http.StatusBadRequest)
						return
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
				fmt.Fprint(w, "700\n512\n"+base64.StdEncoding.EncodeToString([]byte("resume"))+"\n")
			default:
				if uploadStart != 512 || string(ticket) != "resume" {
					t.Errorf("second add-entries upload_start = %d ticket = %q, want 512 and \"resume\"", uploadStart, ticket)
				}
				w.Write(source.checkpointCosignatureLine)
			}
		case "/sign-subtree":
			signSubtreeCalls++
			header, note, ok := bytes.Cut(body, []byte("\n\n"))
			expectHeader := fmt.Sprintf("subtree 0 %d\n%s", source.newer.N, source.newer.Hash)
			if !ok || string(header) != expectHeader {
				t.Errorf("sign-subtree header %q, want %q", header, expectHeader)
			}
			if !bytes.HasSuffix(note, source.checkpointCosignatureLine) {
				t.Errorf("sign-subtree note %q does not end with the add-entries cosignature line", note)
			}
			w.Write([]byte(base64.StdEncoding.EncodeToString(source.subtreeSignature) + "\n"))
		default:
			t.Errorf("unexpected request to %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	m, err := NewMirrorClient(srv.URL, srv.URL, NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey(), 10*time.Second)
	if err != nil {
		t.Fatalf("NewMirrorClient: %s", err)
	}
	checkpointCosignatureLine, err := m.SubmitCheckpoint(t.Context(), source.cp, source.signedNote)
	if err != nil {
		t.Fatalf("SubmitCheckpoint: %s", err)
	}
	mirrored, mirrorLine, err := m.LatestCheckpoint(t.Context(), source.cp.Origin)
	if err != nil {
		t.Fatalf("LatestCheckpoint: %s", err)
	}
	subtreeSignature, err := m.CosignSubtree(t.Context(), mirrored, mirrorLine, 0, source.cp.Tree.N, source.cp.Tree.Hash)
	if err != nil {
		t.Fatalf("CosignSubtree: %s", err)
	}
	if !bytes.Equal(checkpointCosignatureLine, source.checkpointCosignatureLine) {
		t.Errorf("SubmitCheckpoint checkpoint cosignature line = %q, want the add-entries line %q", checkpointCosignatureLine, source.checkpointCosignatureLine)
	}
	if !bytes.Equal(subtreeSignature, source.subtreeSignature) {
		t.Errorf("CosignSubtree = %x, want the mirror's %x", subtreeSignature, source.subtreeSignature)
	}
	if addCheckpointCalls != 2 || addEntriesCalls != 2 || signSubtreeCalls != 1 {
		t.Errorf("mirror saw %d add-checkpoint, %d add-entries, and %d sign-subtree calls, want 2, 2, and 1", addCheckpointCalls, addEntriesCalls, signSubtreeCalls)
	}
}

// TestMirrorCosignAlreadyMirrored covers a publisher starting over against a
// mirror that already holds every entry: add-checkpoint at the mirror's own
// size with an empty proof, then an empty add-entries upload once the mirror
// advertises a next entry equal to the tree size.
func TestMirrorCosignAlreadyMirrored(t *testing.T) {
	source := newSourceLog(t)
	line := string(source.checkpointCosignatureLine)

	var addEntriesCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := requestBody(t, r)
		switch r.URL.Path {
		case "/add-checkpoint":
			if bytes.HasPrefix(body, []byte("old 0\n\n")) {
				w.Header().Set("Content-Type", "text/x.tlog.size")
				w.WriteHeader(http.StatusConflict)
				fmt.Fprintf(w, "%d\n", source.newer.N)
				return
			}
			expect := fmt.Sprintf("old %d\n\n", source.newer.N)
			if !bytes.HasPrefix(body, []byte(expect)) {
				t.Errorf("add-checkpoint body %q does not claim old size %d with an empty proof", body, source.newer.N)
			}
		case "/add-entries":
			addEntriesCalls++
			uploadStart, _ := parseUploadHeader(t, body)
			if addEntriesCalls == 1 {
				w.Header().Set("Content-Type", "text/x.tlog.mirror-info")
				w.WriteHeader(http.StatusAccepted)
				fmt.Fprintf(w, "%d\n%d\n\n", source.newer.N, source.newer.N)
				return
			}
			if uploadStart != source.newer.N {
				t.Errorf("second add-entries upload_start = %d, want %d", uploadStart, source.newer.N)
			}
			fmt.Fprint(w, line)
		default:
			t.Errorf("unexpected request to %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	m, err := NewMirrorClient(srv.URL, srv.URL, NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey(), 10*time.Second)
	if err != nil {
		t.Fatalf("NewMirrorClient: %s", err)
	}
	got, err := m.SubmitCheckpoint(t.Context(), source.cp, source.signedNote)
	if err != nil {
		t.Fatalf("SubmitCheckpoint: %s", err)
	}
	if !bytes.Equal(got, source.checkpointCosignatureLine) {
		t.Errorf("SubmitCheckpoint = %q, want the add-entries line %q", got, source.checkpointCosignatureLine)
	}
	if addEntriesCalls != 2 {
		t.Errorf("mirror saw %d add-entries calls, want 2", addEntriesCalls)
	}
}

// TestMirrorCosignErrors covers the client's failure paths, with a mirror that
// refuses the checkpoint, a mirror demanding an upload_end the checkpoint
// cannot satisfy, and an unreachable mirror.
func TestMirrorCosignErrors(t *testing.T) {
	_, err := NewMirrorClient("", "http://mirror.example", NewSource(nil, testTilePrefix), mirrorID, testKey(t).PublicKey(), 10*time.Second)
	if err == nil {
		t.Error("NewMirrorClient with an empty base URL = nil error, want error")
	}
	_, err = NewMirrorClient("http://mirror.example", "", NewSource(nil, testTilePrefix), mirrorID, testKey(t).PublicKey(), 10*time.Second)
	if err == nil {
		t.Error("NewMirrorClient with an empty monitoring prefix = nil error, want error")
	}

	source := newSourceLog(t)
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "checkpoint refused", http.StatusForbidden)
	}))
	defer refusing.Close()
	m, err := NewMirrorClient(refusing.URL, refusing.URL, NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey(), 10*time.Second)
	if err != nil {
		t.Fatalf("NewMirrorClient: %s", err)
	}
	_, err = m.SubmitCheckpoint(t.Context(), source.cp, source.signedNote)
	if err == nil {
		t.Fatal("SubmitCheckpoint against a refusing mirror = nil error, want error")
	}
	if !strings.Contains(err.Error(), "checkpoint refused") {
		t.Errorf("SubmitCheckpoint error %q does not carry the mirror's response", err)
	}

	overshooting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/add-checkpoint" {
			return
		}
		w.Header().Set("Content-Type", "text/x.tlog.mirror-info")
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, "%d\n%d\n\n", source.newer.N, source.newer.N+1)
	}))
	defer overshooting.Close()
	m, err = NewMirrorClient(overshooting.URL, overshooting.URL, NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey(), 10*time.Second)
	if err != nil {
		t.Fatalf("NewMirrorClient: %s", err)
	}
	_, err = m.SubmitCheckpoint(t.Context(), source.cp, source.signedNote)
	if err == nil {
		t.Fatal("SubmitCheckpoint against a mirror wanting upload_start past the tree size = nil error, want error")
	}
	if !strings.Contains(err.Error(), "upload_start") {
		t.Errorf("SubmitCheckpoint error %q does not name upload_start", err)
	}

	mismatched := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/add-checkpoint" {
			return
		}
		w.Header().Set("Content-Type", "text/x.tlog.mirror-info")
		w.WriteHeader(http.StatusConflict)
		fmt.Fprint(w, "9000\n0\n\n")
	}))
	defer mismatched.Close()
	m, err = NewMirrorClient(mismatched.URL, mismatched.URL, NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey(), 10*time.Second)
	if err != nil {
		t.Fatalf("NewMirrorClient: %s", err)
	}
	_, err = m.SubmitCheckpoint(t.Context(), source.cp, source.signedNote)
	if err == nil || !strings.Contains(err.Error(), "upload_end") {
		t.Errorf("SubmitCheckpoint against a mismatched mirror = %s, want an upload_end error", err)
	}

	conflicting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/x.tlog.size")
		w.WriteHeader(http.StatusConflict)
		fmt.Fprintf(w, "%d\n", source.older.N)
	}))
	defer conflicting.Close()
	m, err = NewMirrorClient(conflicting.URL, conflicting.URL, NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey(), 10*time.Second)
	if err != nil {
		t.Fatalf("NewMirrorClient: %s", err)
	}
	_, err = m.SubmitCheckpoint(t.Context(), source.cp, source.signedNote)
	if err == nil || !strings.Contains(err.Error(), "after retrying") {
		t.Errorf("SubmitCheckpoint against a mirror that keeps answering 409 = %s, want an error after one retry", err)
	}

	// A mirror that answers 202 without saving any package, which the spec
	// rules out, so the upload must end rather than loop.
	stalled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/add-checkpoint" {
			return
		}
		uploadStart, _ := parseUploadHeader(t, requestBody(t, r))
		w.Header().Set("Content-Type", "text/x.tlog.mirror-info")
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, "%d\n%d\n\n", source.newer.N, uploadStart)
	}))
	defer stalled.Close()
	m, err = NewMirrorClient(stalled.URL, stalled.URL, NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey(), 10*time.Second)
	if err != nil {
		t.Fatalf("NewMirrorClient: %s", err)
	}
	_, err = m.SubmitCheckpoint(t.Context(), source.cp, source.signedNote)
	if err == nil || !strings.Contains(err.Error(), "no progress") {
		t.Errorf("SubmitCheckpoint against a mirror that accepts nothing = %s, want a no progress error", err)
	}

	// A checkpoint smaller than the mirror's last cosigned size is a rolled
	// back log, not something to submit.
	accepting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer accepting.Close()
	m, err = NewMirrorClient(accepting.URL, accepting.URL, NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey(), 10*time.Second)
	if err != nil {
		t.Fatalf("NewMirrorClient: %s", err)
	}
	_, err = m.SubmitCheckpoint(t.Context(), source.cp, source.signedNote)
	if err == nil || !strings.Contains(err.Error(), "no cosignature lines") {
		t.Errorf("SubmitCheckpoint against a mirror answering add-entries with an empty 200 = %s, want an error", err)
	}
	m.oldSize = source.newer.N + 1
	_, err = m.SubmitCheckpoint(t.Context(), source.cp, source.signedNote)
	if err == nil || !strings.Contains(err.Error(), "already holds") {
		t.Errorf("SubmitCheckpoint for a tree smaller than the mirror's size = %s, want an error", err)
	}

	unreachable, err := NewMirrorClient("http://127.0.0.1:1", "http://127.0.0.1:1", NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey(), 10*time.Second)
	if err != nil {
		t.Fatalf("NewMirrorClient: %s", err)
	}
	_, err = unreachable.SubmitCheckpoint(t.Context(), source.cp, source.signedNote)
	if err == nil {
		t.Error("SubmitCheckpoint against an unreachable mirror = nil error, want error")
	}

	// A mirror that cosigns the checkpoint with a zero timestamp.
	undated := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/add-checkpoint" {
			return
		}
		w.Write(source.subtreeCosignatureLine)
	}))
	defer undated.Close()
	m, err = NewMirrorClient(undated.URL, undated.URL, NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey(), 10*time.Second)
	if err != nil {
		t.Fatalf("NewMirrorClient: %s", err)
	}
	_, err = m.SubmitCheckpoint(t.Context(), source.cp, source.signedNote)
	if err == nil || !strings.Contains(err.Error(), "zero timestamp") {
		t.Errorf("SubmitCheckpoint with a zero timestamp checkpoint cosignature = %s, want a zero timestamp error", err)
	}

	// A mirror that answers add-entries with a line by another key as well.
	greased := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/add-checkpoint" {
			return
		}
		w.Write(append(slices.Clone(source.checkpointCosignatureLine), greaseLine...))
	}))
	defer greased.Close()
	m, err = NewMirrorClient(greased.URL, greased.URL, NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey(), 10*time.Second)
	if err != nil {
		t.Fatalf("NewMirrorClient: %s", err)
	}
	checkpointCosignatureLine, err := m.SubmitCheckpoint(t.Context(), source.cp, source.signedNote)
	if err != nil {
		t.Errorf("SubmitCheckpoint with a line by another key in the add-entries response: %s", err)
	}
	if !bytes.Equal(checkpointCosignatureLine, source.checkpointCosignatureLine) {
		t.Errorf("SubmitCheckpoint with a line by another key in the add-entries response = %q, want the mirror's line %q", checkpointCosignatureLine, source.checkpointCosignatureLine)
	}

	// A mirror whose checkpoint does not include the subtree yet.
	_, err = m.CosignSubtree(t.Context(), &checkpoint.Checkpoint{Origin: source.cp.Origin, Tree: source.older}, nil, 0, source.cp.Tree.N, source.cp.Tree.Hash)
	if err == nil || !strings.Contains(err.Error(), "does not include") {
		t.Errorf("CosignSubtree against a mirror behind the subtree = %s, want an error", err)
	}

	// A mirror whose checkpoint at the subtree's size has a different root.
	_, err = m.CosignSubtree(t.Context(), &checkpoint.Checkpoint{Origin: source.cp.Origin, Tree: tlog.Tree{N: source.newer.N, Hash: source.older.Hash}}, nil, 0, source.cp.Tree.N, source.cp.Tree.Hash)
	if err == nil || !strings.Contains(err.Error(), "root hash") {
		t.Errorf("CosignSubtree against a mirror with a different root = %s, want a root hash error", err)
	}
}
