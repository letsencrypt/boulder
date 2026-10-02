package mtcb

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	"github.com/letsencrypt/boulder/trees/entry"
	"github.com/letsencrypt/boulder/trees/issuancelog"
	"github.com/letsencrypt/boulder/trees/proof"
	"github.com/letsencrypt/boulder/trees/pubkey"
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

// fakeCheckpointDB serves the first checkpoint whose tree size covers the
// entry.
type fakeCheckpointDB struct {
	checkpoints        []*treedb.CheckpointModel
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

func (f *fakeCheckpointDB) LatestCheckpoint(_ context.Context, mtcLogID string) (*treedb.CheckpointModel, error) {
	if len(f.checkpoints) == 0 {
		return nil, fmt.Errorf("no checkpoints")
	}
	return f.checkpoints[len(f.checkpoints)-1], nil
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
	fs3                *bs3test.FakeS3
	entries            []issued
	checkpoints        []*treedb.CheckpointModel
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
		log.checkpoints = append(log.checkpoints, &treedb.CheckpointModel{
			ID:              int64(len(log.checkpoints) + 1),
			MTCLogID:        testLogID.String(),
			MTCASignature:   fmt.Appendf(nil, "placeholder mtca signature over size %d", frontier.TreeSize()),
			MirrorID:        &mirrorID,
			MirrorSignature: fmt.Appendf(nil, "placeholder mirror signature over size %d", frontier.TreeSize()),
			TreeSize:        frontier.TreeSize(),
			RootHash:        root[:],
		})
		log.checkpointSubtrees = append(log.checkpointSubtrees, &treedb.CheckpointSubtreeModel{
			ID:              int64(len(log.checkpoints) + 1),
			MTCLogID:        testLogID.String(),
			MTCASignature:   fmt.Appendf(nil, "placeholder mtca signature over size %d", frontier.TreeSize()),
			MirrorID:        &mirrorID,
			MirrorSignature: fmt.Appendf(nil, "placeholder mirror signature over size %d", frontier.TreeSize()),
			SubtreeStart:    0,
			SubtreeEnd:      uint64(frontier.TreeSize()), //nolint:gosec // G115: guaranteed non-negative by Frontier.
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

// testMTCB returns an mtcb over checkpoints and the tiles in fs3.
func testMTCB(t *testing.T, fs3 *bs3test.FakeS3, checkpoints []*treedb.CheckpointModel, subtrees []*treedb.CheckpointSubtreeModel) *mtcb {
	t.Helper()
	issuer, err := issuance.LoadCertificate("../test/certs/mtpki/mtca1.cert.pem")
	if err != nil {
		t.Fatalf("LoadCertificate: %s", err)
	}
	fakeDB := &fakeCheckpointDB{
		checkpoints:        checkpoints,
		checkpointSubtrees: subtrees,
	}
	m, err := New([]*issuance.Certificate{issuer}, fakeDB, fs3, blog.NewMock(), clock.NewFake())
	if err != nil {
		t.Fatalf("New: %s", err)
	}
	return m
}

// verifyStandalone checks that certDER is a standalone certificate for expected
// that proves inclusion to subtree and carries its cosignatures.
func (l *testLog) verifyStandalone(t *testing.T, certDER []byte, expected issued, subtree *treedb.CheckpointSubtreeModel) {
	t.Helper()
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %s", err)
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
	if mtcProof.Start != subtree.SubtreeStart {
		t.Errorf("start = %d, want %d", mtcProof.Start, subtree.SubtreeStart)
	}
	if mtcProof.End != subtree.SubtreeEnd {
		t.Errorf("end = %d, want %d", mtcProof.End, subtree.SubtreeEnd)
	}

	// TODO: This test fetches the hash of the MTCLogEntry at index `expected.index` and verifies the proof against that.
	// Instead it should calculate the hash based purely on the `certDER`, following the algorithm at
	// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-verifying-certificate-signa
	subtreeEnd := int64(subtree.SubtreeEnd) //nolint:gosec // G115: SubtreeEnd fits an int64 in this test.
	tree := tlog.Tree{N: subtreeEnd, Hash: tlog.Hash(subtree.SubtreeHash)}
	hr := tlog.TileHashReader(tree, tiles.NewTileReader(t.Context(), l.fs3, testLogID.TilePrefix()))
	leafHashes, err := hr.ReadHashes([]int64{tlog.StoredHashIndex(0, expected.index)})
	if err != nil {
		t.Fatalf("reading the leaf hash from tile storage: %s", err)
	}
	mtcLogEntryHash := leafHashes[0]

	err = tlog.CheckRecord(mtcProof.InclusionProof, subtreeEnd, tree.Hash, expected.index, mtcLogEntryHash)
	if err != nil {
		t.Errorf("inclusion proof is not for index %d in the checkpoint of tree size %d: %s", expected.index, subtree.SubtreeEnd, err)
	}

	if len(mtcProof.Signatures) != 2 {
		t.Fatalf("got %d cosignatures, want 2", len(mtcProof.Signatures))
	}
	sigsByID := map[string][]byte{}
	for _, sig := range mtcProof.Signatures {
		sigsByID[string(sig.CosignerID)] = sig.Signature
	}
	if !bytes.Equal(sigsByID[testLogID.CAID], subtree.MTCASignature) {
		t.Errorf("MTCA cosignature = %x, want %x", sigsByID[testLogID.CAID], subtree.MTCASignature)
	}
	if !bytes.Equal(sigsByID[mirrorID], subtree.MirrorSignature) {
		t.Errorf("mirror cosignature = %x, want %x", sigsByID[mirrorID], subtree.MirrorSignature)
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
		latest  *treedb.CheckpointModel
		subtree *treedb.CheckpointSubtreeModel
	}{
		{name: "Partial first bundle at size 4", entries: l.entries[1:4], latest: l.checkpoints[0], subtree: l.checkpointSubtrees[0]},
		{name: "Partial first bundle at size 6", entries: l.entries[4:6], latest: l.checkpoints[1], subtree: l.checkpointSubtrees[1]},
		{name: "Full first bundle", entries: l.entries[6:8], latest: l.checkpoints[2], subtree: l.checkpointSubtrees[2]},
		{name: "Across the bundle boundary", entries: l.entries[254:], latest: l.checkpoints[2], subtree: l.checkpointSubtrees[2]},
		{name: "Size 4 subtree under the size 258 checkpoint", entries: l.entries[1:4], latest: l.checkpoints[2], subtree: l.checkpointSubtrees[0]},
		{name: "Size 6 subtree under the size 258 checkpoint", entries: l.entries[4:6], latest: l.checkpoints[2], subtree: l.checkpointSubtrees[1]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := testMTCB(t, l.fs3, []*treedb.CheckpointModel{tc.latest}, l.checkpointSubtrees)
			for _, expected := range tc.entries {
				resp, err := m.GetStandalone(t.Context(), &mtcbpb.StandaloneRequest{
					MtcLogID:        testLogID.String(),
					MtcSerialNumber: expected.serial,
					MtcSubtreeID:    tc.subtree.ID,
				})
				if err != nil {
					t.Fatalf("GetStandalone for serial %016x: %s", expected.serial, err)
				}
				l.verifyStandalone(t, resp.CertDER, expected, tc.subtree)
			}
		})
	}
}

func TestGetStandaloneInvalidCheckpoint(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name              string
		mutateLatest      func(*treedb.CheckpointModel)
		mutateSubtree     func(*treedb.CheckpointSubtreeModel)
		expectErrContains string
	}{
		{
			name:              "Latest checkpoint with a short root hash",
			mutateLatest:      func(cp *treedb.CheckpointModel) { cp.RootHash = make([]byte, 5) },
			expectErrContains: "validating checkpoint 1:",
		},
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
			if tc.mutateLatest != nil {
				tc.mutateLatest(latest)
			}
			if tc.mutateSubtree != nil {
				tc.mutateSubtree(subtree)
			}
			m := testMTCB(t, bs3test.New(), []*treedb.CheckpointModel{latest}, []*treedb.CheckpointSubtreeModel{subtree})
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
			m := testMTCB(t, bs3test.New(), nil, nil)
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
	m := testMTCB(t, bs3test.New(), nil, []*treedb.CheckpointSubtreeModel{mirrored, unmirrored})
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
