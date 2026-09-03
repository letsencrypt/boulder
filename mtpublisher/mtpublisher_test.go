//go:build go1.27

package mtpublisher

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/bs3/bs3test"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/mtpublisher/mtpublishertest"
	"github.com/letsencrypt/boulder/privatekey"
	"github.com/letsencrypt/boulder/trees/checkpoint"
	"github.com/letsencrypt/boulder/trees/cosignature"
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

var testLogID = issuancelog.ID{CAID: "44947.4.1", LogNumber: 44}

// fakeCheckpointDB holds the latest checkpoint of one log, or none for a log
// that is not initialized, and stores the mirror cosignature on it. The mtca
// tests truncate the mtcmeta database and run in parallel with these, so they
// cannot share it.
type fakeCheckpointDB struct {
	latest *treedb.CheckpointModel
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

// testPublisher returns a publisher over checkpoints whose mirror cosigns with
// key.
func testPublisher(t *testing.T, key *mldsa.PrivateKey, checkpoints *fakeCheckpointDB) *mtpublisher {
	t.Helper()
	p, err := New(nil, time.Second, testLogID, testCAKey(t).PublicKey(), testMirror(t, key), blog.NewMock())
	if err != nil {
		t.Fatalf("New: %s", err)
	}
	p.treedb = checkpoints
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

// caSignature returns the raw MTCA signature for a checkpoint of treeSize with
// a zero root hash, as testCheckpoint holds.
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

// testCheckpoint returns a checkpoint of treeSize with a zero root hash, signed
// by the MTCA and awaiting the mirror cosignature.
func testCheckpoint(t *testing.T, treeSize int64) *treedb.CheckpointModel {
	t.Helper()
	return &treedb.CheckpointModel{
		ID:            1,
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
	err := p.Publish(t.Context())
	if err != nil {
		t.Fatalf("p.Publish() on a log that is not initialized: %s", err)
	}

	// The latest checkpoint, which we expect to be cosigned by p.Publish().
	latest := testCheckpoint(t, 512)
	checkpoints.latest = latest

	err = p.Publish(t.Context())
	if err != nil {
		t.Fatalf("p.Publish(): %s", err)
	}

	if latest.MirrorID == nil {
		t.Fatal("latest checkpoint was not cosigned")
	}
	if *latest.MirrorID != mirrorID {
		t.Errorf("mirrorID = %q, want %q", *latest.MirrorID, mirrorID)
	}
	if len(latest.MirrorSignature) != mldsa.MLDSA44SignatureSize {
		t.Fatalf("latest checkpoint's mirrorSignature is %d bytes, want %d", len(latest.MirrorSignature), mldsa.MLDSA44SignatureSize)
	}

	verifier, err := cosignature.NewVerifier(mirrorID, key.PublicKey())
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}
	text := "oid/1.3.6.1.4.1." + mtcLogID + "\n512\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
	timestampedSignature := append(make([]byte, 8), latest.MirrorSignature...)
	if !verifier.Verify([]byte(text), timestampedSignature) {
		t.Error("stored mirror cosignature does not verify against the checkpoint text")
	}
}

// TestPublishRejectsBadMTCASignature checks that a checkpoint whose stored
// MTCA signature does not verify is neither submitted nor cosigned.
func TestPublishRejectsBadMTCASignature(t *testing.T) {
	// A well-formed MTCA signature over the wrong tree size.
	latest := testCheckpoint(t, 512)
	latest.MTCASignature = caSignature(t, 999)
	p := testPublisher(t, testKey(t), &fakeCheckpointDB{latest: latest})

	err := p.Publish(t.Context())
	if err == nil {
		t.Error("publish with a bad MTCA signature = nil error, want error")
	}
	if latest.MirrorID != nil || latest.MirrorSignature != nil {
		t.Error("cosignature was stored despite the MTCA signature failing verification")
	}
}

// TestPublishMirrorError checks that a failed cosigning stores nothing.
func TestPublishMirrorError(t *testing.T) {
	latest := testCheckpoint(t, 512)
	p := testPublisher(t, testKey(t), &fakeCheckpointDB{latest: latest})
	otherLogMirror, err := mtpublishertest.NewTestMirror(mirrorID, "oid/1.3.6.1.4.1.44947.4.2.0.99", privatekey.NewDeterministicSigner(testKey(t)))
	if err != nil {
		t.Fatalf("NewTestMirror: %s", err)
	}
	p.mirror = otherLogMirror

	err = p.Publish(t.Context())
	if err == nil {
		t.Error("publish with a mirror refusing the checkpoint = nil error, want error")
	}
	if latest.MirrorID != nil || latest.MirrorSignature != nil {
		t.Error("cosignature was stored despite the mirror refusing the checkpoint")
	}
}

func TestPublishWhenLatestAlreadySigned(t *testing.T) {
	// The latest checkpoint is already cosigned, which must be left untouched.
	existingMirrorID := "existing.cosigner"
	latest := testCheckpoint(t, 512)
	latest.MirrorID = &existingMirrorID
	latest.MirrorSignature = []byte("already-signed-bruh")
	p := testPublisher(t, testKey(t), &fakeCheckpointDB{latest: latest})

	err := p.Publish(t.Context())
	if err != nil {
		t.Fatalf("p.Publish(): %s", err)
	}

	if *latest.MirrorID != existingMirrorID || string(latest.MirrorSignature) != "already-signed-bruh" {
		t.Errorf("existing cosignature was replaced: %s %q", *latest.MirrorID, latest.MirrorSignature)
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
	caLine, err := cosignature.SignatureLine(caVerifier.Name(), caVerifier.KeyHash(), 0, rawCA)
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
	cosigLine, err := cosignature.SignatureLine(mirrorVerifier.Name(), mirrorVerifier.KeyHash(), 0, rawCosig)
	if err != nil {
		t.Fatalf("SignatureLine: %s", err)
	}
	return &sourceLog{
		fs3: fs3, older: older, newer: newer, cp: cp, signedNote: signedNote,
		mirrorKey: mirrorKey, cosigLine: cosigLine, rawCosig: rawCosig,
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
	originLen := int(binary.BigEndian.Uint16(body[:2]))
	rest := body[2+originLen:]
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
				fmt.Fprint(w, line)
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
			fmt.Fprint(w, line)
		default:
			t.Errorf("unexpected request to %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	m, err := NewMirrorClient(srv.URL, NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey(), 10*time.Second)
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

// TestMirrorCosignAlreadyMirrored covers a publisher starting over against a
// mirror that already holds every entry: add-checkpoint at the mirror's own
// size with an empty proof, then an empty add-entries upload once the mirror
// advertises a next entry equal to the tree size.
func TestMirrorCosignAlreadyMirrored(t *testing.T) {
	source := newSourceLog(t)
	line := string(source.cosigLine)

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
		case "/sign-subtree":
			fmt.Fprint(w, line)
		default:
			t.Errorf("unexpected request to %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	m, err := NewMirrorClient(srv.URL, NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey(), 10*time.Second)
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
	if addEntriesCalls != 2 {
		t.Errorf("mirror saw %d add-entries calls, want 2", addEntriesCalls)
	}
}

// TestMirrorCosignErrors covers the client's failure paths, with a mirror that
// refuses the checkpoint, a mirror demanding an upload_end the checkpoint
// cannot satisfy, and an unreachable mirror.
func TestMirrorCosignErrors(t *testing.T) {
	_, err := NewMirrorClient("", NewSource(nil, testTilePrefix), mirrorID, testKey(t).PublicKey(), 10*time.Second)
	if err == nil {
		t.Error("NewMirrorClient with an empty base URL = nil error, want error")
	}

	source := newSourceLog(t)
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "checkpoint refused", http.StatusForbidden)
	}))
	defer refusing.Close()
	m, err := NewMirrorClient(refusing.URL, NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey(), 10*time.Second)
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

	overshooting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/add-checkpoint" {
			return
		}
		w.Header().Set("Content-Type", "text/x.tlog.mirror-info")
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, "%d\n%d\n\n", source.newer.N, source.newer.N+1)
	}))
	defer overshooting.Close()
	m, err = NewMirrorClient(overshooting.URL, NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey(), 10*time.Second)
	if err != nil {
		t.Fatalf("NewMirrorClient: %s", err)
	}
	_, err = m.Cosign(t.Context(), source.cp, source.signedNote)
	if err == nil {
		t.Fatal("Cosign against a mirror wanting upload_start past the tree size = nil error, want error")
	}
	if !strings.Contains(err.Error(), "upload_start") {
		t.Errorf("Cosign error %q does not name upload_start", err)
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
	m, err = NewMirrorClient(mismatched.URL, NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey(), 10*time.Second)
	if err != nil {
		t.Fatalf("NewMirrorClient: %s", err)
	}
	_, err = m.Cosign(t.Context(), source.cp, source.signedNote)
	if err == nil || !strings.Contains(err.Error(), "upload_end") {
		t.Errorf("Cosign against a mismatched mirror = %s, want an upload_end error", err)
	}

	conflicting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/x.tlog.size")
		w.WriteHeader(http.StatusConflict)
		fmt.Fprintf(w, "%d\n", source.older.N)
	}))
	defer conflicting.Close()
	m, err = NewMirrorClient(conflicting.URL, NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey(), 10*time.Second)
	if err != nil {
		t.Fatalf("NewMirrorClient: %s", err)
	}
	_, err = m.Cosign(t.Context(), source.cp, source.signedNote)
	if err == nil || !strings.Contains(err.Error(), "after retrying") {
		t.Errorf("Cosign against a mirror that keeps answering 409 = %s, want an error after one retry", err)
	}

	// A checkpoint smaller than the mirror's last cosigned size is a rolled
	// back log, not something to submit.
	accepting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer accepting.Close()
	m, err = NewMirrorClient(accepting.URL, NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey(), 10*time.Second)
	if err != nil {
		t.Fatalf("NewMirrorClient: %s", err)
	}
	_, err = m.Cosign(t.Context(), source.cp, source.signedNote)
	if err == nil || !strings.Contains(err.Error(), "no cosignature lines") {
		t.Errorf("Cosign against a mirror answering add-entries with an empty 200 = %s, want an error", err)
	}
	m.oldSize = source.newer.N + 1
	_, err = m.Cosign(t.Context(), source.cp, source.signedNote)
	if err == nil || !strings.Contains(err.Error(), "already holds") {
		t.Errorf("Cosign for a tree smaller than the mirror's size = %s, want an error", err)
	}

	unreachable, err := NewMirrorClient("http://127.0.0.1:1", NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey(), 10*time.Second)
	if err != nil {
		t.Fatalf("NewMirrorClient: %s", err)
	}
	_, err = unreachable.Cosign(t.Context(), source.cp, source.signedNote)
	if err == nil {
		t.Error("Cosign against an unreachable mirror = nil error, want error")
	}

	// A mirror whose signature line names its key but was signed by another,
	// so the signature is checked and rejected rather than ignored as unknown.
	forger, err := cosignature.NewCosigner(mirrorID, source.cp.Origin, privatekey.NewDeterministicSigner(testKey(t)))
	if err != nil {
		t.Fatalf("NewCosigner: %s", err)
	}
	forgedTimestamped, err := forger.CosignCheckpoint(source.newer)
	if err != nil {
		t.Fatalf("CosignCheckpoint: %s", err)
	}
	forgedRaw, err := cosignature.RawSignature(forgedTimestamped)
	if err != nil {
		t.Fatalf("RawSignature: %s", err)
	}
	mirrorVerifier, err := cosignature.NewVerifier(mirrorID, source.mirrorKey.PublicKey())
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}
	forgedLine, err := cosignature.SignatureLine(mirrorVerifier.Name(), mirrorVerifier.KeyHash(), 0, forgedRaw)
	if err != nil {
		t.Fatalf("SignatureLine: %s", err)
	}
	lying := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/add-checkpoint" {
			return
		}
		w.Write(forgedLine)
	}))
	defer lying.Close()
	m, err = NewMirrorClient(lying.URL, NewSource(source.fs3, testTilePrefix), mirrorID, source.mirrorKey.PublicKey(), 10*time.Second)
	if err != nil {
		t.Fatalf("NewMirrorClient: %s", err)
	}
	_, err = m.Cosign(t.Context(), source.cp, source.signedNote)
	_, ok := errors.AsType[*note.InvalidSignatureError](err)
	if !ok {
		t.Errorf("Cosign with a forged signature = %s, want note.InvalidSignatureError", err)
	}
}
