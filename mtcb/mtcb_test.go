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

func TestSplitMTCSerial(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name             string
		serial           uint64
		expectLogNum     uint16
		expectEntryIndex uint64
	}{
		{name: "Log one", serial: 1<<entryIndexBits | 5, expectLogNum: 1, expectEntryIndex: 5},
		{name: "Max values", serial: 0xffffffffffffffff, expectLogNum: 0xffff, expectEntryIndex: 1<<entryIndexBits - 1},
		{name: "High bit set", serial: 0x8000<<entryIndexBits | 1, expectLogNum: 0x8000, expectEntryIndex: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			logNum, entryIndex := splitMTCSerial(tc.serial)
			if logNum != tc.expectLogNum {
				t.Errorf("log number = %d, want %d", logNum, tc.expectLogNum)
			}
			if entryIndex != tc.expectEntryIndex {
				t.Errorf("entry index = %d, want %d", entryIndex, tc.expectEntryIndex)
			}
		})
	}
}

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
	tbs, err := mtcle.ToTBSCertificate(1<<entryIndexBits|7, orig.RawSubjectPublicKeyInfo, crypto.SHA256)
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
	checkpoints []*treedb.CheckpointModel
}

func (f *fakeCheckpointDB) ContainingCheckpoint(_ context.Context, mtcLogID string, entryIndex int64) (*treedb.CheckpointModel, error) {
	for _, cp := range f.checkpoints {
		if cp.MTCLogID == mtcLogID && cp.TreeSize > entryIndex {
			return cp, nil
		}
	}
	return nil, fmt.Errorf("no checkpoint of %q covers index %d", mtcLogID, entryIndex)
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
	fs3         *bs3test.FakeS3
	entries     []issued
	checkpoints []*treedb.CheckpointModel
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
	}
	return log
}

// testSerial returns the serial of the entry at index in testLogID.
func testSerial(index int64) uint64 {
	return uint64(testLogID.LogNumber)<<entryIndexBits | uint64(index) //nolint:gosec // G115: indices in this test are tiny.
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
		serial:  testSerial(index),
		spki:    spki,
		dnsName: dnsName,
	}
}

// testMTCB returns an mtcb over checkpoints and the tiles in fs3.
func testMTCB(t *testing.T, fs3 *bs3test.FakeS3, checkpoints []*treedb.CheckpointModel) *mtcb {
	t.Helper()
	issuer, err := issuance.LoadCertificate("../test/certs/mtpki/mtca1.cert.pem")
	if err != nil {
		t.Fatalf("LoadCertificate: %s", err)
	}
	m, err := New([]*issuance.Certificate{issuer}, &fakeCheckpointDB{checkpoints: checkpoints}, fs3, blog.NewMock(), clock.NewFake())
	if err != nil {
		t.Fatalf("New: %s", err)
	}
	return m
}

// verifyStandalone checks that certDER is a standalone certificate for expected
// that proves inclusion to cp and carries its cosignatures.
func (l *testLog) verifyStandalone(t *testing.T, certDER []byte, expected issued, cp *treedb.CheckpointModel) {
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
	if mtcProof.Start != 0 {
		t.Errorf("start = %d, want 0", mtcProof.Start)
	}
	if mtcProof.End != uint64(cp.TreeSize) { //nolint:gosec // G115: tree sizes in this test are tiny.
		t.Errorf("end = %d, want %d", mtcProof.End, cp.TreeSize)
	}

	tree := tlog.Tree{N: cp.TreeSize, Hash: tlog.Hash(cp.RootHash)}
	hr := tlog.TileHashReader(tree, tiles.NewTileReader(t.Context(), l.fs3, testLogID.TilePrefix()))
	leafHashes, err := hr.ReadHashes([]int64{tlog.StoredHashIndex(0, expected.index)})
	if err != nil {
		t.Fatalf("reading the leaf hash from tile storage: %s", err)
	}
	err = tlog.CheckRecord(mtcProof.InclusionProof, cp.TreeSize, tree.Hash, expected.index, leafHashes[0])
	if err != nil {
		t.Errorf("inclusion proof is not for index %d in the checkpoint of tree size %d: %s", expected.index, cp.TreeSize, err)
	}

	if len(mtcProof.Signatures) != 2 {
		t.Fatalf("got %d cosignatures, want 2", len(mtcProof.Signatures))
	}
	sigsByID := map[string][]byte{}
	for _, sig := range mtcProof.Signatures {
		sigsByID[string(sig.CosignerID)] = sig.Signature
	}
	if !bytes.Equal(sigsByID[testLogID.CAID], cp.MTCASignature) {
		t.Errorf("MTCA cosignature = %x, want %x", sigsByID[testLogID.CAID], cp.MTCASignature)
	}
	if !bytes.Equal(sigsByID[mirrorID], cp.MirrorSignature) {
		t.Errorf("mirror cosignature = %x, want %x", sigsByID[mirrorID], cp.MirrorSignature)
	}
}

// TestGetStandalone checks that every certificate in the log is built from its
// own entry and proves inclusion to the checkpoint served for it.
func TestGetStandalone(t *testing.T) {
	t.Parallel()
	l := newTestLog(t)
	m := testMTCB(t, l.fs3, l.checkpoints)

	// Reading each range under its own checkpoint checks that bundles are read
	// at that checkpoint's width, in both bundles.
	for _, tc := range []struct {
		name    string
		entries []issued
		cp      *treedb.CheckpointModel
	}{
		{name: "Partial first bundle at size 4", entries: l.entries[1:4], cp: l.checkpoints[0]},
		{name: "Partial first bundle at size 6", entries: l.entries[4:6], cp: l.checkpoints[1]},
		{name: "Full first bundle", entries: l.entries[6:8], cp: l.checkpoints[2]},
		{name: "Across the bundle boundary", entries: l.entries[254:], cp: l.checkpoints[2]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, expected := range tc.entries {
				resp, err := m.GetStandalone(t.Context(), &mtcbpb.StandaloneRequest{MtcLogID: testLogID.String(), Serial: expected.serial})
				if err != nil {
					t.Fatalf("GetStandalone for serial %d: %s", expected.serial, err)
				}
				l.verifyStandalone(t, resp.CertDER, expected, tc.cp)
			}
		})
	}
}

func TestGetStandaloneInvalidCheckpoint(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name              string
		cp                *treedb.CheckpointModel
		expectErrContains string
	}{
		{
			name: "Short root hash",
			cp: &treedb.CheckpointModel{
				ID:              1,
				MTCLogID:        testLogID.String(),
				TreeSize:        4,
				RootHash:        make([]byte, 5),
				MTCASignature:   []byte("mtca"),
				MirrorID:        &mirrorID,
				MirrorSignature: []byte("mirror"),
			},
			expectErrContains: "validating checkpoint",
		},
		{
			name: "No mirror ID",
			cp: &treedb.CheckpointModel{
				ID:              1,
				MTCLogID:        testLogID.String(),
				TreeSize:        4,
				RootHash:        make([]byte, 32),
				MTCASignature:   []byte("mtca"),
				MirrorSignature: []byte("mirror"),
			},
			expectErrContains: "not mirrored",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := testMTCB(t, bs3test.New(), []*treedb.CheckpointModel{tc.cp})
			_, err := m.GetStandalone(t.Context(), &mtcbpb.StandaloneRequest{MtcLogID: testLogID.String(), Serial: testSerial(1)})
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
	serial := testSerial(1)
	otherLog := issuancelog.ID{CAID: testLogID.CAID, LogNumber: testLogID.LogNumber + 1}

	for _, tc := range []struct {
		name              string
		req               *mtcbpb.StandaloneRequest
		expectErrContains string
	}{
		{"Empty log ID", &mtcbpb.StandaloneRequest{Serial: serial}, "incomplete"},
		{"Zero serial", &mtcbpb.StandaloneRequest{MtcLogID: testLogID.String()}, "incomplete"},
		{"Malformed log ID", &mtcbpb.StandaloneRequest{MtcLogID: testLogID.CAID, Serial: serial}, "before its log number"},
		{"Unknown CA", &mtcbpb.StandaloneRequest{MtcLogID: "32473.9.0.5", Serial: serial}, "unrecognized MTCA ID"},
		{"Log number mismatch", &mtcbpb.StandaloneRequest{MtcLogID: otherLog.String(), Serial: serial}, "encodes log number"},
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
