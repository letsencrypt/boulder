package mtcb

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/bs3/bs3test"
	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	mtcbpb "github.com/letsencrypt/boulder/mtcb/proto"
	"github.com/letsencrypt/boulder/privatekey"
	"github.com/letsencrypt/boulder/trees/checkpoint"
	"github.com/letsencrypt/boulder/trees/cosignature"
	"github.com/letsencrypt/boulder/trees/entry"
	"github.com/letsencrypt/boulder/trees/issuancelog"
	"github.com/letsencrypt/boulder/trees/proof"
	"github.com/letsencrypt/boulder/trees/pubkey"
	"github.com/letsencrypt/boulder/trees/subtree"
	"github.com/letsencrypt/boulder/trees/tiles"
	"github.com/letsencrypt/boulder/trees/treedb"
)

var mirrorID = "32473.9"

var testLogID = issuancelog.ID{CAID: "44947.4.1", LogNumber: 5}

// TestBuildCertificate checks that buildCertificate's output parses as a
// Certificate.
func TestBuildCertificate(t *testing.T) {
	t.Parallel()
	orig, err := core.LoadCert("../test/hierarchy/ee-e1.cert.pem")
	if err != nil {
		t.Fatalf("LoadCert: %s", err)
	}
	mtcle, err := entry.FromX509(orig.Raw, crypto.SHA256)
	if err != nil {
		t.Fatalf("FromX509: %s", err)
	}
	tbs, err := mtcle.ToTBSCertificate(testSerial(t, 7), orig.RawSubjectPublicKeyInfo, crypto.SHA256)
	if err != nil {
		t.Fatalf("ToTBSCertificate: %s", err)
	}

	sig := proof.MTCProof{
		Start:          0,
		End:            8,
		InclusionProof: []tlog.Hash{{1}, {2}, {3}},
		Signatures: []*proof.SubtreeSignature{
			{CosignerID: []byte(testLogID.CAID), Signature: []byte("mtca sig")},
			{CosignerID: []byte(mirrorID), Signature: []byte("mirror sig")},
		},
	}
	expectSig, err := sig.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %s", err)
	}

	certBytes, err := buildCertificate(tbs, &sig)
	if err != nil {
		t.Fatalf("buildCertificate: %s", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %s", err)
	}

	if !bytes.Equal(cert.RawTBSCertificate, tbs) {
		t.Errorf("tbsCertificate = %x, want %x", cert.RawTBSCertificate, tbs)
	}
	if !bytes.Equal(cert.Signature, expectSig) {
		t.Errorf("signature = %x, want %x", cert.Signature, expectSig)
	}
}

// fakeCheckpointDB serves checkpoint subtrees by log ID and subtree ID.
type fakeCheckpointDB struct {
	checkpointSubtrees []*treedb.CheckpointSubtreeModel
}

func (f *fakeCheckpointDB) GetCheckpointSubtree(_ context.Context, mtcLogID string, id int64) (*treedb.CheckpointSubtreeModel, error) {
	for _, subtree := range f.checkpointSubtrees {
		if subtree.MTCLogID == mtcLogID && subtree.ID == id {
			return subtree, nil
		}
	}
	return nil, berrors.NotFoundError("not found")
}

// issued is one entry in the test log, along with the values we expect to find
// in the standalone certificate the mtcb builds for it.
type issued struct {
	index   int64
	serial  uint64
	spki    []byte
	dnsName string
}

// testLog is an issuance log and the checkpoints that cover it.
type testLog struct {
	fs3     *bs3test.FakeS3
	entries []issued
	// signedNotes are the CA-signed checkpoints at each published tree size, in
	// order. The last one is also stored at the checkpoint path in fs3.
	signedNotes        [][]byte
	checkpointSubtrees []*treedb.CheckpointSubtreeModel
}

// newTestLog returns a log containing 257 certificates, published with mirrored
// checkpoints at tree sizes 4, 6, and 258.
func newTestLog(t *testing.T) *testLog {
	t.Helper()
	log := &testLog{fs3: bs3test.New()}
	frontier := &tiles.Frontier{}
	err := frontier.AppendEntry(&entry.MTCLogEntry{}, &pubkey.MTCPublicKey{})
	if err != nil {
		t.Fatalf("AppendEntry: %s", err)
	}
	log.entries = append(log.entries, issued{})

	signer := newSigner(t)

	for _, batch := range []int{3, 2, 252} {
		for range batch {
			index := int64(len(log.entries))
			log.entries = append(log.entries, log.appendCertificate(t, frontier, index))
		}
		err := frontier.Publish(t.Context(), log.fs3, testLogID.TilePrefix())
		if err != nil {
			t.Fatalf("Publish: %s", err)
		}
		root := frontier.RootHash()
		signedNote := signer.checkpointSignedNote(t, &treedb.CheckpointModel{
			TreeSize: frontier.TreeSize(),
			RootHash: root[:],
		})
		log.fs3.Objects[testLogID.CheckpointPath()] = bs3test.StoredObject{
			Data: signedNote,
		}
		log.signedNotes = append(log.signedNotes, signedNote)

		log.checkpointSubtrees = append(log.checkpointSubtrees, &treedb.CheckpointSubtreeModel{
			ID:              int64(len(log.checkpointSubtrees) + 1),
			MTCLogID:        testLogID.String(),
			MTCASignature:   fmt.Appendf(nil, "placeholder mtca signature over size %d", frontier.TreeSize()),
			MirrorID:        &mirrorID,
			MirrorSignature: fmt.Appendf(nil, "placeholder mirror signature over size %d", frontier.TreeSize()),
			SubtreeStart:    0,
			SubtreeEnd:      uint64(frontier.TreeSize()), //nolint:gosec // G115: tree sizes in this test are tiny.
			SubtreeHash:     root[:],
		})
	}
	return log
}

// testSerial returns the serial of the entry at index in testLogID.
func testSerial(t *testing.T, index int64) uint64 {
	t.Helper()
	serial, err := core.EncodeMTCSerial(testLogID.LogNumber, index)
	if err != nil {
		t.Fatalf("EncodeMTCSerial: %s", err)
	}
	return serial
}

// appendCertificate appends the log entry and public key of a new certificate
// for a random DNS name under example.com.
func (l *testLog) appendCertificate(t *testing.T, f *tiles.Frontier, index int64) issued {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %s", err)
	}
	var buf [4]byte
	_, err = rand.Read(buf[:])
	if err != nil {
		t.Fatalf("rand.Read: %s", err)
	}
	dnsName := fmt.Sprintf("%x.example.com", buf)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(index),
		DNSNames:     []string{dnsName},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2026, 1, 8, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %s", err)
	}
	mtcle, err := entry.FromX509(certDER, crypto.SHA256)
	if err != nil {
		t.Fatalf("FromX509: %s", err)
	}
	mtcpk, err := pubkey.FromCryptoPubkey(key.Public())
	if err != nil {
		t.Fatalf("FromCryptoPubkey: %s", err)
	}
	err = f.AppendEntry(mtcle, mtcpk)
	if err != nil {
		t.Fatalf("AppendEntry: %s", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %s", err)
	}
	return issued{
		index:   index,
		serial:  testSerial(t, index),
		spki:    spki,
		dnsName: dnsName,
	}
}

// testMTCB returns an mtcb over subtrees and the checkpoint and tiles in fs3.
func testMTCB(t *testing.T, fs3 *bs3test.FakeS3, subtrees []*treedb.CheckpointSubtreeModel) *mtcb {
	t.Helper()
	issuer, err := issuance.LoadCertificate("../test/certs/mtpki/mtca1.cert.pem")
	if err != nil {
		t.Fatalf("LoadCertificate: %s", err)
	}
	fakeDB := &fakeCheckpointDB{
		checkpointSubtrees: subtrees,
	}
	m, err := New([]*issuance.Certificate{issuer}, fakeDB, fs3, blog.NewMock(), clock.NewFake())
	if err != nil {
		t.Fatalf("New: %s", err)
	}
	return m
}

type signer struct {
	logID    issuancelog.ID
	cosigner *cosignature.Cosigner
	caPubKey crypto.PublicKey
}

// newCosigner returns a *cosignature.Cosigner that signs with the given privKey over the log
// with the given origin, and uses `cosignerID` as its name.
func newCosigner(t *testing.T, privKeyPath, cosignerID, origin string) (*cosignature.Cosigner, crypto.PublicKey) {
	privKey, _, err := privatekey.Load(privKeyPath)
	if err != nil {
		t.Fatal(err)
	}

	co, err := cosignature.NewCosigner(cosignerID, origin, privKey)
	if err != nil {
		t.Fatal(err)
	}

	return co, privKey.Public()
}

// newSigner returns a *signer that signs checkpoints of testLogID as the CA.
func newSigner(t *testing.T) *signer {
	return newSignerForLog(t, testLogID)
}

// newSignerForLog returns a *signer that signs checkpoints of the given logID with the CA's key.
func newSignerForLog(t *testing.T, logID issuancelog.ID) *signer {
	ca, caPubKey := newCosigner(t, "../test/certs/mtpki/mtca1.key.pem", logID.CAID, logID.Origin())
	return &signer{
		logID:    logID,
		cosigner: ca,
		caPubKey: caPubKey,
	}
}

// checkpointSignedNote signs the checkpoint with the CA key and returns a signed note.
//
// It disregards the MTCASignature and MirrorSignature fields of the dbCheckpoint.
func (s *signer) checkpointSignedNote(t *testing.T, dbCheckpoint *treedb.CheckpointModel) []byte {
	tree := tlog.Tree{
		N:    dbCheckpoint.TreeSize,
		Hash: tlog.Hash(dbCheckpoint.RootHash),
	}

	caSig, err := s.cosigner.CosignCheckpoint(tree)
	if err != nil {
		t.Fatalf("cosigning checkpoint: %s", err)
	}

	caCosignatureLine, err := s.cosigner.SignatureLine(0, caSig[8:])
	if err != nil {
		t.Fatalf("building CA signature line: %s", err)
	}

	noteText, err := (&checkpoint.Checkpoint{Origin: s.logID.Origin(), Tree: tree}).Marshal()
	if err != nil {
		t.Fatal(err)
	}

	signedNote := append(noteText, '\n')
	signedNote = append(signedNote, caCosignatureLine...)

	verifier, err := cosignature.NewVerifier(s.logID.CAID, s.caPubKey.(*mldsa.PublicKey))
	if err != nil {
		t.Fatalf("creating CA verifier: %s", err)
	}

	_, _, err = checkpoint.Open(signedNote, verifier)
	if err != nil {
		t.Fatalf("self-verifying checkpoint: %s", err)
	}

	return signedNote
}

// verifyStandalone checks that certDER is a standalone certificate for expected
// that proves inclusion to dbSubtree's rootHash and carries its cosignatures.
func verifyStandalone(t *testing.T, certDER []byte, expected issued, dbSubtree *treedb.CheckpointSubtreeModel) {
	t.Helper()
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %s", err)
	}
	if !cert.SerialNumber.IsUint64() {
		t.Fatalf("serial number %x is not representable as a uint64", cert.SerialNumber)
	}
	if cert.SerialNumber.Uint64() != expected.serial {
		t.Errorf("serial = %d, want %d", cert.SerialNumber.Uint64(), expected.serial)
	}
	if !slices.Equal(cert.DNSNames, []string{expected.dnsName}) {
		t.Errorf("DNSNames = %q, want %q", cert.DNSNames, []string{expected.dnsName})
	}
	if !bytes.Equal(cert.RawSubjectPublicKeyInfo, expected.spki) {
		t.Errorf("subjectPublicKeyInfo = %x, want %x", cert.RawSubjectPublicKeyInfo, expected.spki)
	}

	mtcProof, err := proof.UnmarshalMTCProof(cert.Signature)
	if err != nil {
		t.Fatalf("UnmarshalMTCProof: %s", err)
	}
	if mtcProof.Start != dbSubtree.SubtreeStart {
		t.Errorf("start = %d, want %d", mtcProof.Start, dbSubtree.SubtreeStart)
	}
	if mtcProof.End != dbSubtree.SubtreeEnd {
		t.Errorf("end = %d, want %d", mtcProof.End, dbSubtree.SubtreeEnd)
	}

	_, entryIndex, err := core.DecodeMTCSerial(cert.SerialNumber.Uint64())
	if err != nil {
		t.Fatal(err)
	}

	mtcle, err := entry.FromX509(certDER, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	mtcleMarshaled, err := mtcle.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	expectedSubtreeHash, err := subtree.HashFromProof(
		tlog.RecordHash(mtcleMarshaled),
		mtcProof.InclusionProof,
		entryIndex,
		int64(mtcProof.Start), //nolint:gosec // G115: we know these are < 1<<48 in tests
		int64(mtcProof.End),   //nolint:gosec // G115: we know these are < 1<<48 in tests
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dbSubtree.SubtreeHash, expectedSubtreeHash[:]) {
		t.Errorf("subtree hash from database (%s) != HashFromProof(%s)", tlog.Hash(dbSubtree.SubtreeHash), expectedSubtreeHash)
	}

	// TODO: sign real signatures in the test and validate them here.
	if len(mtcProof.Signatures) != 2 {
		t.Fatalf("got %d cosignatures, want 2", len(mtcProof.Signatures))
	}
	sigsByID := map[string][]byte{}
	for _, sig := range mtcProof.Signatures {
		sigsByID[string(sig.CosignerID)] = sig.Signature
	}
	if !bytes.Equal(sigsByID[testLogID.CAID], dbSubtree.MTCASignature) {
		t.Errorf("MTCA cosignature = %x, want %x", sigsByID[testLogID.CAID], dbSubtree.MTCASignature)
	}
	if !bytes.Equal(sigsByID[mirrorID], dbSubtree.MirrorSignature) {
		t.Errorf("mirror cosignature = %x, want %x", sigsByID[mirrorID], dbSubtree.MirrorSignature)
	}
}

// TestGetStandalone checks that every certificate in the log is built from its
// own entry and proves inclusion to the checkpoint served for it.
func TestGetStandalone(t *testing.T) {
	t.Parallel()
	l := newTestLog(t)

	// Call GetStandalone for a variety of subtrees. For each one, use a `latest` checkpoint that
	// has a TreeSize equal to SubtreeEnd, to exercise the partial-tile fetch path, and where the
	// log has grown past it, a later one.
	for _, tc := range []struct {
		name    string
		entries []issued
		// latest is the signed note served at the checkpoint path for this case.
		latest  []byte
		subtree *treedb.CheckpointSubtreeModel
	}{
		{name: "Partial first bundle at size 4", entries: l.entries[1:4], latest: l.signedNotes[0], subtree: l.checkpointSubtrees[0]},
		{name: "Partial first bundle at size 6", entries: l.entries[4:6], latest: l.signedNotes[1], subtree: l.checkpointSubtrees[1]},
		{name: "Full first bundle", entries: l.entries[6:8], latest: l.signedNotes[2], subtree: l.checkpointSubtrees[2]},
		{name: "Across the bundle boundary", entries: l.entries[254:], latest: l.signedNotes[2], subtree: l.checkpointSubtrees[2]},
		{name: "Size 4 subtree under the size 258 checkpoint", entries: l.entries[1:4], latest: l.signedNotes[2], subtree: l.checkpointSubtrees[0]},
		{name: "Size 6 subtree under the size 258 checkpoint", entries: l.entries[4:6], latest: l.signedNotes[2], subtree: l.checkpointSubtrees[1]},
	} {
		// Serve this case's checkpoint. The cases share one fs3, so the subtests
		// below must not run in parallel.
		l.fs3.Objects[testLogID.CheckpointPath()] = bs3test.StoredObject{Data: tc.latest}
		for _, expected := range tc.entries {
			m := testMTCB(t, l.fs3, l.checkpointSubtrees)
			t.Run(fmt.Sprintf("%s/%016x", tc.name, expected.serial), func(t *testing.T) {
				resp, err := m.GetStandalone(t.Context(), &mtcbpb.StandaloneRequest{
					MtcLogID:        testLogID.String(),
					MtcSerialNumber: expected.serial,
					MtcSubtreeID:    tc.subtree.ID,
				})
				if err != nil {
					t.Fatalf("GetStandalone for serial %016x: %s", expected.serial, err)
				}
				verifyStandalone(t, resp.CertDER, expected, tc.subtree)
			})
		}
	}
}

func TestGetStandaloneInvalidSubtree(t *testing.T) {
	t.Parallel()
	signer := newSigner(t)
	for _, tc := range []struct {
		name              string
		mutateSubtree     func(*treedb.CheckpointSubtreeModel)
		expectErrContains string
	}{
		{
			name:              "Subtree with a short hash",
			mutateSubtree:     func(st *treedb.CheckpointSubtreeModel) { st.SubtreeHash = make([]byte, 5) },
			expectErrContains: "validating checkpoint subtree",
		},
		{
			name:              "Subtree with no mirror ID",
			mutateSubtree:     func(st *treedb.CheckpointSubtreeModel) { st.MirrorID = nil },
			expectErrContains: "not ready",
		},
		{
			name:              "Subtree past the latest checkpoint",
			mutateSubtree:     func(st *treedb.CheckpointSubtreeModel) { st.SubtreeEnd = 6 },
			expectErrContains: "subtreeEnd is greater than treeSize",
		},
		{
			name:              "Subtree that does not include the entry",
			mutateSubtree:     func(st *treedb.CheckpointSubtreeModel) { st.SubtreeEnd = 1 },
			expectErrContains: "not in subtree",
		},
		{
			name:              "Subtree starting past the first entry",
			mutateSubtree:     func(st *treedb.CheckpointSubtreeModel) { st.SubtreeStart = 1 },
			expectErrContains: "not yet supported",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			latest := &treedb.CheckpointModel{
				ID:       1,
				MTCLogID: testLogID.String(),
				TreeSize: 4,
				RootHash: make([]byte, 32),
			}

			signedNote := signer.checkpointSignedNote(t, latest)
			fs3 := bs3test.New()
			fs3.Objects[testLogID.CheckpointPath()] = bs3test.StoredObject{
				Data: signedNote,
			}

			subtree := &treedb.CheckpointSubtreeModel{
				ID:              1,
				MTCLogID:        testLogID.String(),
				MTCASignature:   []byte("mtca"),
				MirrorID:        &mirrorID,
				MirrorSignature: []byte("mirror"),
				SubtreeStart:    0,
				SubtreeEnd:      4,
				SubtreeHash:     make([]byte, 32),
			}
			if tc.mutateSubtree != nil {
				tc.mutateSubtree(subtree)
			}
			m := testMTCB(t, fs3, []*treedb.CheckpointSubtreeModel{subtree})
			_, err := m.GetStandalone(t.Context(), &mtcbpb.StandaloneRequest{
				MtcLogID:        testLogID.String(),
				MtcSerialNumber: testSerial(t, 1),
				MtcSubtreeID:    subtree.ID,
			})
			if err == nil {
				t.Fatal("GetStandalone: got nil error, want error")
			}
			if !strings.Contains(err.Error(), tc.expectErrContains) {
				t.Errorf("GetStandalone: got %q, want it to contain %q", err, tc.expectErrContains)
			}
		})
	}
}

// TestGetStandaloneInvalidCheckpoint tests that a missing or corrupted checkpoint
// file leads to an error.
func TestGetStandaloneInvalidCheckpoint(t *testing.T) {
	t.Parallel()
	validNote := newSigner(t).checkpointSignedNote(t, &treedb.CheckpointModel{
		TreeSize: 4,
		RootHash: make([]byte, 32),
	})

	// The same checkpoint, validly signed by the same CA, but for a different log.
	otherLog := issuancelog.ID{CAID: testLogID.CAID, LogNumber: testLogID.LogNumber + 1}
	otherLogNote := newSignerForLog(t, otherLog).checkpointSignedNote(t, &treedb.CheckpointModel{
		TreeSize: 4,
		RootHash: make([]byte, 32),
	})

	for _, tc := range []struct {
		name string
		// signedNote is the object stored at the checkpoint path. If nil, no
		// object is stored.
		signedNote        []byte
		expectErrContains string
	}{
		{
			name:              "No checkpoint in tile storage",
			signedNote:        nil,
			expectErrContains: "getting latest checkpoint: reading s3://fakebucket/" + testLogID.CheckpointPath(),
		},
		{
			name:              "Checkpoint altered after signing",
			signedNote:        bytes.Replace(validNote, []byte("\n4\n"), []byte("\n5\n"), 1),
			expectErrContains: "getting latest checkpoint: invalid signature",
		},
		{
			name:              "Checkpoint for a different log",
			signedNote:        otherLogNote,
			expectErrContains: fmt.Sprintf("origin %q doesn't match expected %q", otherLog.Origin(), testLogID.Origin()),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fs3 := bs3test.New()
			if tc.signedNote != nil {
				fs3.Objects[testLogID.CheckpointPath()] = bs3test.StoredObject{
					Data: tc.signedNote,
				}
			}

			subtree := &treedb.CheckpointSubtreeModel{
				ID:              1,
				MTCLogID:        testLogID.String(),
				MTCASignature:   []byte("mtca"),
				MirrorID:        &mirrorID,
				MirrorSignature: []byte("mirror"),
				SubtreeStart:    0,
				SubtreeEnd:      4,
				SubtreeHash:     make([]byte, 32),
			}
			m := testMTCB(t, fs3, []*treedb.CheckpointSubtreeModel{subtree})
			_, err := m.GetStandalone(t.Context(), &mtcbpb.StandaloneRequest{
				MtcLogID:        testLogID.String(),
				MtcSerialNumber: testSerial(t, 1),
				MtcSubtreeID:    subtree.ID,
			})
			if err == nil {
				t.Fatal("GetStandalone: got nil error, want error")
			}
			if !strings.Contains(err.Error(), tc.expectErrContains) {
				t.Errorf("GetStandalone: got %q, want it to contain %q", err, tc.expectErrContains)
			}
		})
	}
}

func TestGetStandaloneRejectsBadRequests(t *testing.T) {
	t.Parallel()
	serial := testSerial(t, 1)
	otherLog := issuancelog.ID{CAID: testLogID.CAID, LogNumber: testLogID.LogNumber + 1}

	for _, tc := range []struct {
		name              string
		req               *mtcbpb.StandaloneRequest
		expectErrContains string
	}{
		{"Empty log ID", &mtcbpb.StandaloneRequest{MtcSerialNumber: serial, MtcSubtreeID: 123}, "incomplete"},
		{"Zero serial", &mtcbpb.StandaloneRequest{MtcLogID: testLogID.String(), MtcSubtreeID: 123}, "incomplete"},
		{"Zero subtreeID", &mtcbpb.StandaloneRequest{MtcLogID: testLogID.String(), MtcSerialNumber: serial}, "incomplete"},
		{"Malformed log ID", &mtcbpb.StandaloneRequest{MtcLogID: testLogID.CAID, MtcSerialNumber: serial, MtcSubtreeID: 123}, "before its log number"},
		{"Unknown CA", &mtcbpb.StandaloneRequest{MtcLogID: "32473.9.0.5", MtcSerialNumber: serial, MtcSubtreeID: 123}, "no issuer configured"},
		{"Log number mismatch", &mtcbpb.StandaloneRequest{MtcLogID: otherLog.String(), MtcSerialNumber: serial, MtcSubtreeID: 123}, "encodes log number"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := testMTCB(t, bs3test.New(), nil)
			_, err := m.GetStandalone(t.Context(), tc.req)
			if err == nil {
				t.Fatal("GetStandalone: got nil error, want error")
			}
			if !strings.Contains(err.Error(), tc.expectErrContains) {
				t.Errorf("GetStandalone: got %q, want it to contain %q", err, tc.expectErrContains)
			}
		})
	}
}

func TestStandaloneReady(t *testing.T) {
	t.Parallel()
	mirrored := &treedb.CheckpointSubtreeModel{
		ID:              456,
		MTCLogID:        testLogID.String(),
		MTCASignature:   []byte("mtca"),
		MirrorID:        &mirrorID,
		MirrorSignature: []byte("mirror"),
		SubtreeStart:    0,
		SubtreeEnd:      3,
		SubtreeHash:     make([]byte, 32),
	}
	unmirrored := &treedb.CheckpointSubtreeModel{
		ID:            457,
		MTCLogID:      testLogID.String(),
		MTCASignature: []byte("mtca"),
		SubtreeStart:  0,
		SubtreeEnd:    3,
		SubtreeHash:   make([]byte, 32),
	}
	m := testMTCB(t, bs3test.New(), []*treedb.CheckpointSubtreeModel{mirrored, unmirrored})
	otherLog := issuancelog.ID{CAID: testLogID.CAID, LogNumber: testLogID.LogNumber + 1}

	for _, tc := range []struct {
		name              string
		req               *mtcbpb.StandaloneReadyRequest
		expectReady       bool
		expectErrContains string
	}{
		{
			name: "Mirrored subtree",
			req: &mtcbpb.StandaloneReadyRequest{
				MtcLogID:        testLogID.String(),
				MtcSerialNumber: testSerial(t, 2),
				MtcSubtreeID:    mirrored.ID,
			},
			expectReady: true,
		},
		{
			name: "Unmirrored subtree",
			req: &mtcbpb.StandaloneReadyRequest{
				MtcLogID:        testLogID.String(),
				MtcSerialNumber: testSerial(t, 2),
				MtcSubtreeID:    unmirrored.ID,
			},
			expectReady: false,
		},
		{
			name: "Nonexistent subtree ID",
			req: &mtcbpb.StandaloneReadyRequest{
				MtcLogID:        testLogID.String(),
				MtcSerialNumber: testSerial(t, 2),
				MtcSubtreeID:    999999,
			},
			expectErrContains: "not found",
		},
		{
			name: "Serial outside the subtree",
			req: &mtcbpb.StandaloneReadyRequest{
				MtcLogID:        testLogID.String(),
				MtcSerialNumber: testSerial(t, 3),
				MtcSubtreeID:    mirrored.ID,
			},
			expectErrContains: "not in subtree",
		},
		{
			name: "Log number mismatch",
			req: &mtcbpb.StandaloneReadyRequest{
				MtcLogID:        otherLog.String(),
				MtcSerialNumber: testSerial(t, 2),
				MtcSubtreeID:    mirrored.ID,
			},
			expectErrContains: "encodes log number",
		},
		{
			name: "Unknown CA",
			req: &mtcbpb.StandaloneReadyRequest{
				MtcLogID:        "32473.9.0.5",
				MtcSerialNumber: testSerial(t, 2),
				MtcSubtreeID:    mirrored.ID,
			},
			expectErrContains: "no issuer configured",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp, err := m.StandaloneReady(t.Context(), tc.req)
			if tc.expectErrContains != "" {
				if err == nil {
					t.Fatal("StandaloneReady: got nil error, want error")
				}
				if !strings.Contains(err.Error(), tc.expectErrContains) {
					t.Errorf("StandaloneReady: got %q, want it to contain %q", err, tc.expectErrContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("StandaloneReady: %s", err)
			}
			if resp.Ready != tc.expectReady {
				t.Errorf("StandaloneReady: ready = %t, want %t", resp.Ready, tc.expectReady)
			}
		})
	}
}
