//go:build go1.27

package mtca

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jmhodges/clock"

	"github.com/letsencrypt/borp"

	"github.com/letsencrypt/boulder/bs3/bs3test"
	"github.com/letsencrypt/boulder/config"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/mtca/proto"
	"github.com/letsencrypt/boulder/mtpublisher"
	"github.com/letsencrypt/boulder/privatekey"
	"github.com/letsencrypt/boulder/test/vars"
	"github.com/letsencrypt/boulder/trees/cosigned"
	"github.com/letsencrypt/boulder/trees/entry"
	"github.com/letsencrypt/boulder/trees/issuancelog"
	"github.com/letsencrypt/boulder/trees/tiles"
)

// setup returns a working mtca, its fake tile storage, and a cleanup
// function, or an error.
func setup() (*mtca, *bs3test.FakeS3, func(), error) {
	issuer, err := issuance.LoadIssuer(issuance.IssuerConfig{
		Profiles:   []string{"some profile"},
		IssuerURL:  "http://ignored.letsencrypt.org",
		CRLURLBase: "http://ignored.letsencrypt.org/",
		CRLShards:  1,
		Location: issuance.IssuerLoc{
			File:     "../test/certs/mtpki/mtca1.key.pem",
			CertFile: "../test/certs/mtpki/mtca1.cert.pem",
		},
	}, clock.NewFake())
	if err != nil {
		return nil, nil, nil, err
	}

	db, err := sql.Open("mysql", vars.DBConnMTCMeta_44947_4_1_0_44FullPerms)
	if err != nil {
		return nil, nil, nil, err
	}
	dbMap := &borp.DbMap{Db: db, Dialect: borp.MySQLDialect{}}
	err = truncateTables(db)
	if err != nil {
		return nil, nil, nil, err
	}

	logger := blog.NewMock()
	clk := clock.NewFake()

	profile, err := issuance.NewProfile(issuance.ProfileConfig{
		OmitCommonName:      true,
		OmitKeyEncipherment: true,
		OmitClientAuth:      true,
		OmitSKID:            true,
		MTC:                 true,
		MaxValidityPeriod:   config.Duration{Duration: time.Hour},
		LintConfig:          "",
		IgnoredLints: []string{
			"w_ext_subject_key_identifier_missing_sub_cert",
			"w_ct_sct_policy_count_unsatisfied",
			"e_signature_algorithm_not_supported",
		},
	})
	if err != nil {
		return nil, nil, nil, err
	}

	fs3 := bs3test.New()
	mtca, err := New(
		issuer,
		map[string]*issuance.Profile{"mtcExample": profile},
		issuancelog.ID{CAID: "44947.4.1", LogNumber: 44},
		100*time.Millisecond,
		dbMap,
		fs3,
		logger,
		clk)
	if err != nil {
		return nil, nil, nil, err
	}

	err = mtca.InitLog(context.Background())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("initializing log: %w", err)
	}

	cleanup := func() {
		_ = truncateTables(db)
	}

	return mtca, fs3, cleanup, nil
}

func TestPool(t *testing.T) {
	p := &pool{maxSize: 20}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Go(func() {
			err := p.append(pendingEntry{})
			if err != nil {
				t.Errorf("appending entry: %s", err)
			}
		})
	}
	wg.Wait()

	err := p.append(pendingEntry{})
	if err == nil {
		t.Errorf("append to full pool: got nil, want err")
	}

	length := p.len()
	if length != 20 {
		t.Errorf("p.len(): got %d, want 20", length)
	}

	entries := p.take()
	if len(entries) != 20 {
		t.Errorf("p.take(): got %d entries, want 20", len(entries))
	}

	length = p.len()
	if length != 0 {
		t.Errorf("p.len(): got %d after take, want 0", length)
	}
}

func TestCheckpointValid(t *testing.T) {
	type testCase struct {
		name  string
		value checkpoint
	}

	rootHash := [32]byte{}

	testCases := []testCase{
		{"no MTCLogID", checkpoint{ID: 7, TreeSize: 9, RootHash: rootHash[:]}},
		{"no TreeSize", checkpoint{ID: 7, MTCLogID: "TestLog", RootHash: rootHash[:]}},
		{"short RootHash", checkpoint{ID: 7, MTCLogID: "TestLog", TreeSize: 9, RootHash: rootHash[:4]}},
		{"no RootHash", checkpoint{ID: 7, MTCLogID: "TestLog", TreeSize: 9}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.value.valid()
			if err == nil {
				t.Errorf("checkpoint.valid(): got nil, want error")
			}
		})
	}

	goodCheckpoint := checkpoint{
		ID:       7,
		MTCLogID: "TestLog",
		TreeSize: 9,
		RootHash: rootHash[:],
	}

	err := goodCheckpoint.valid()
	if err != nil {
		t.Errorf("goodCheckpoint.valid(): got %q, want no error", err)
	}
}

func truncateTables(db *sql.DB) error {
	_, err := db.Exec("TRUNCATE TABLE checkpoints")
	if err != nil {
		return err
	}
	_, err = db.Exec("TRUNCATE TABLE latestCheckpoint")
	if err != nil {
		return err
	}
	return nil
}

// issueResult is the outcome of one async Issue call, along with the values
// we expect to find in the entry sequenced for it.
type issueResult struct {
	*proto.IssueResponse
	err              error
	expectedSPKIHash [sha256.Size]byte
	expectedDNSName  string
}

// makeIssueRequest returns an IssueRequest with a freshly generated key and
// a random DNS name under example.com.
func makeIssueRequest(t *testing.T) *proto.IssueRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		t.Fatalf("generating key: %s", err)
	}
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatalf("marshaling pubkey: %s", err)
	}

	var buf [4]byte
	_, err = rand.Read(buf[:])
	if err != nil {
		t.Fatalf("generating random DNS name: %s", err)
	}
	dnsName := fmt.Sprintf("%x.example.com", buf)

	return &proto.IssueRequest{
		Pubkey: pubkeyBytes,
		Identifiers: []*corepb.Identifier{
			{Type: "dns", Value: dnsName},
		},
		Profile: "mtcExample",
	}
}

// issueMany calls Issue() `n` times concurrently and waits for all of the requests
// to be included in the pool. Returns a channel that will supply results once `Issue()`
// returns.
//
// Does not call `sequence()`. The caller is responsible for that.
func issueMany(t *testing.T, m *mtca, n int) <-chan issueResult {
	t.Helper()
	ch := make(chan issueResult, n)
	for i := 0; i < n; i++ {
		req := makeIssueRequest(t)
		go func() {
			resp, err := m.Issue(t.Context(), req)
			ch <- issueResult{
				IssueResponse:    resp,
				err:              err,
				expectedSPKIHash: sha256.Sum256(req.Pubkey),
				expectedDNSName:  req.Identifiers[0].Value,
			}
		}()
	}

	// Waiting for inclusion in the pool lets us check "pool full" conditions.
	for m.pool.len() < n {
		time.Sleep(time.Millisecond)
	}
	return ch
}

// errorS3 wraps a bs3test.FakeS3, failing every PutObject with `err` while
// it is non-nil and passing through to the wrapped fake otherwise.
type errorS3 struct {
	*bs3test.FakeS3
	err error
}

func (e *errorS3) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if e.err != nil {
		return nil, e.err
	}
	return e.FakeS3.PutObject(ctx, params, optFns...)
}

// mirrorCosign cosigns the latest checkpoint with a real mtpublisher, standing
// in for the daemon, so sequencing can proceed.
func mirrorCosign(t *testing.T, m *mtca) {
	t.Helper()
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), make([]byte, 32))
	if err != nil {
		t.Fatalf("NewPrivateKey: %s", err)
	}
	p, err := mtpublisher.New(m.db, time.Second, m.logID, "32473.9", privatekey.NewDeterministicSigner(key), key.PublicKey(), blog.NewMock())
	if err != nil {
		t.Fatalf("mtpublisher.New: %s", err)
	}
	err = p.Publish(t.Context())
	if err != nil {
		t.Fatalf("mtpublisher.Publish: %s", err)
	}
}

// verifyStores checks at a given point in time that tree size and root hash
// are the same between:
//
//   - m.frontier
//   - m.latestCheckpoint()
//   - fake tile storage
func verifyStores(t *testing.T, m *mtca, fs3 *bs3test.FakeS3) *checkpoint {
	t.Helper()
	latest, err := m.latestCheckpoint(t.Context())
	if err != nil {
		t.Fatalf("getting latest: %s", err)
	}

	memTreeSize := m.frontier.TreeSize()
	if memTreeSize != latest.TreeSize {
		t.Errorf("in-memory frontier TreeSize %d != DB TreeSize %d", memTreeSize, latest.TreeSize)
	}
	memHash := m.frontier.RootHash()
	if !bytes.Equal(latest.RootHash, memHash[:]) {
		t.Errorf("in-memory frontier RootHash %s != DB RootHash %s",
			memHash, base64.StdEncoding.EncodeToString(latest.RootHash))
	}

	loaded, err := tiles.LoadFrontier(t.Context(), fs3, latest.TreeSize, m.logID.TilePrefix())
	if err != nil {
		t.Fatalf("loading frontier from tile storage: %s", err)
	}
	tileHash := loaded.RootHash()
	if !bytes.Equal(latest.RootHash, tileHash[:]) {
		t.Errorf("tile storage RootHash %s != DB RootHash %s",
			tileHash, base64.StdEncoding.EncodeToString(latest.RootHash))
	}
	return latest
}

// validateStoredEntries reads and parses the rightmost entries tile from
// storage, then verifies that the entry at each index in `got` contains the
// SPKI hash and DNS name of the request that was assigned that index.
//
// Only valid for tree sizes below 256.
func validateStoredEntries(t *testing.T, fs3 *bs3test.FakeS3, prefix string, treeSize int64, got map[int64]issueResult) {
	t.Helper()
	obj, ok := fs3.Objects[fmt.Sprintf("%s/tile/entries/000.p/%d", prefix, treeSize)]
	if !ok {
		t.Fatalf("no entries tile in storage for tree size %d", treeSize)
	}
	data := obj.Data
	if obj.ContentEncoding != nil && *obj.ContentEncoding == "gzip" {
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("decompressing entries tile: %s", err)
		}
		data, err = io.ReadAll(r)
		if err != nil {
			t.Fatalf("decompressing entries tile: %s", err)
		}
	}
	br := entry.NewBundleReader(data)
	var entries []*entry.MTCLogEntry
	for {
		mtcle, _, err := br.ReadEntry()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("parsing entries tile: %s", err)
		}
		entries = append(entries, mtcle)
	}
	if int64(len(entries)) != treeSize {
		t.Fatalf("entries tile at tree size %d: got %d entries", treeSize, len(entries))
	}

	for idx, res := range got {
		tbs := entries[idx].TBS()
		if !bytes.Contains(tbs, res.expectedSPKIHash[:]) {
			t.Errorf("entry at index %d does not contain the SPKI hash of the request that was assigned that index", idx)
		}
		if !bytes.Contains(tbs, []byte(res.expectedDNSName)) {
			t.Errorf("entry at index %d does not contain the DNS name %q of the request that was assigned that index", idx, res.expectedDNSName)
		}
	}
}

// collectResults reads n results. The entryIndexes must exactly cover [firstIndex, firstIndex+n).
//
// Returns a map from entry index to the result of the request that received that index.
func collectResults(t *testing.T, results <-chan issueResult, firstIndex int64, n int) map[int64]issueResult {
	t.Helper()
	got := map[int64]issueResult{}
	for i := 0; i < n; i++ {
		res := <-results
		if res.err != nil {
			t.Errorf("Issue: %s", res.err)
			continue
		}
		_, ok := got[res.MtcEntryIndex]
		if ok {
			t.Errorf("entryIndex %d returned twice", res.MtcEntryIndex)
		}
		got[res.MtcEntryIndex] = res
	}
	for i := firstIndex; i < firstIndex+int64(n); i++ {
		_, ok := got[i]
		if !ok {
			t.Errorf("no Issue call got entryIndex %d", i)
		}
	}
	return got
}

func TestSequence(t *testing.T) {
	mtca, fs3, cleanup, err := setup()
	if err != nil {
		t.Fatalf("setting up mtca: %s", err)
	}
	t.Cleanup(cleanup)
	// An empty pool is a no-op regardless of checkpoint state.
	err = mtca.sequence(t.Context())
	if err != nil {
		t.Fatalf("sequencing with empty pool: %s", err)
	}
	// Fill the pool with five concurrent requests.
	mtca.pool.maxSize = 5
	results := issueMany(t, mtca, 5)

	// With the pool full, a sixth request should fail.
	req := makeIssueRequest(t)
	_, err = mtca.Issue(t.Context(), req)
	if err == nil {
		t.Fatal("Issue with a full pool: got nil error, want error")
	}
	if !strings.Contains(err.Error(), "pool is full") {
		t.Errorf("Issue with a full pool: expected 'pool is full', got %q", err)
	}
	// The checkpoint has no mirror signature yet, so sequencing must fail.
	err = mtca.sequence(t.Context())
	if err == nil {
		t.Fatalf("sequencing with an unready checkpoint: got nil error, want error")
	}
	if !errors.Is(err, ErrCheckpointNotReady) {
		t.Errorf("sequencing with an unready checkpoint: want ErrCheckpointNotReady, got %q", err)
	}
	if mtca.pool.len() != 5 {
		t.Errorf("pool after refused sequencing: got len %d, want 5", mtca.pool.len())
	}

	mirrorCosign(t, mtca)

	// Now sequencing should succeed, assigning indexes 1 through 5 (the
	// genesis null entry occupies index 0).
	err = mtca.sequence(t.Context())
	if err != nil {
		t.Fatalf("sequencing with waiting entries: %s", err)
	}
	got := collectResults(t, results, 1, 5)

	// The in-memory frontier, DB checkpoint, and stored tiles must agree,
	// and the resulting checkpoint signature must be valid.
	latest := verifyStores(t, mtca, fs3)
	verifyCheckpoint(t, mtca, latest)

	// Each client's returned index must point at its own entry in the
	// published entries tile.
	validateStoredEntries(t, fs3, mtca.logID.TilePrefix(), latest.TreeSize, got)
}

// TestSequenceStorageFailure checks that a failed sequencing pass leaves the
// in-memory frontier consistent with the database, and that sequencing
// recovers cleanly once storage is healthy again.
func TestSequenceStorageFailure(t *testing.T) {
	mtca, fs3, cleanup, err := setup()
	if err != nil {
		t.Fatalf("setting up mtca: %s", err)
	}
	t.Cleanup(cleanup)
	mirrorCosign(t, mtca)

	mtca.pool.maxSize = 2
	results := issueMany(t, mtca, 2)

	// Fail writing the tiles.
	es3 := &errorS3{FakeS3: fs3, err: errors.New("the tiles will not tesselate")}
	mtca.s3c = es3
	err = mtca.sequence(t.Context())
	if err == nil {
		t.Fatal("sequencing with failing storage: got nil error, want error")
	}
	if !strings.Contains(err.Error(), "staging") {
		t.Errorf("sequencing with failing storage: got %q, want a staging error", err)
	}

	// The waiting RPCs should get their responses.
	for i := 0; i < 2; i++ {
		res := <-results
		if res.err == nil {
			t.Errorf("Issue with failing storage: got entryIndex %d, want error", res.MtcEntryIndex)
		}
	}

	// The in-memory frontier must be unchanged, still matching the DB.
	verifyStores(t, mtca, fs3)

	// Storage is working again!
	es3.err = nil
	results = issueMany(t, mtca, 2)
	err = mtca.sequence(t.Context())
	if err != nil {
		t.Fatalf("sequencing after storage recovered: %s", err)
	}
	// After storage recovered, we should pick up where we left off
	// and sequence 2 entries starting at entryIndex 1.
	got := collectResults(t, results, 1, 2)

	latest := verifyStores(t, mtca, fs3)
	verifyCheckpoint(t, mtca, latest)

	validateStoredEntries(t, fs3, mtca.logID.TilePrefix(), latest.TreeSize, got)
}

func TestInitLog(t *testing.T) {
	mtca, _, cleanup, err := setup()
	if err != nil {
		t.Fatalf("setting up mtca: %s", err)
	}
	defer cleanup()

	// InitLog is called once by setup. A second time should fail.
	err = mtca.InitLog(t.Context())
	if err == nil {
		t.Errorf("second InitLog: got nil error, want error")
	}

	latest, err := mtca.latestCheckpoint(t.Context())
	if err != nil {
		t.Fatalf("getting latest: %s", err)
	}

	if latest.TreeSize != 1 {
		t.Errorf("just-initialized log: got TreeSize %d, want 1", latest.TreeSize)
	}
	expected, _ := hex.DecodeString("8855508aade16ec573d21e6a485dfd0a7624085c1a14b5ecdd6485de0c6839a4")
	if !bytes.Equal(latest.RootHash, expected) {
		t.Errorf("just-initialized log: got RootHash %x, want %x", latest.RootHash, expected)
	}

	verifyCheckpoint(t, mtca, latest)
}

func verifyCheckpoint(t *testing.T, mtca *mtca, checkpoint *checkpoint) {
	t.Helper()
	message := cosigned.Message{
		CosignerName: "oid/1.3.6.1.4.1." + mtca.logID.CAID,
		Timestamp:    0,
		LogOrigin:    mtca.logID.Origin(),
		Start:        0,
		End:          uint64(checkpoint.TreeSize), //nolint:gosec // G115: we know that tree sizes are positive in these tests
		SubtreeHash:  [32]byte(checkpoint.RootHash),
	}

	marshaled, err := message.Marshal()
	if err != nil {
		t.Fatalf("marshaling cosigned.Message: %s", err)
	}

	pubkey, ok := mtca.issuer.Signer.Public().(*mldsa.PublicKey)
	if !ok {
		t.Fatalf("issuer pubkey: got %T, want %T", mtca.issuer.Signer.Public(), &mldsa.PublicKey{})
	}

	err = mldsa.Verify(pubkey, marshaled, checkpoint.MTCASignature, nil)
	if err != nil {
		t.Errorf("verifying MTCASignature: %s", err)
	}
}

func TestGetCAID(t *testing.T) {
	certBytes, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(`
MIIBRjCB9KADAgECAgF7MAoGCCqGSM49BAMCMBsxGTAXBgorBgEEAYLaSy8BDAk0
NDk0Ny40LjEwHhcNMjYwNzE0MjIyNjIwWhcNMzYwNzExMjIyNjIwWjAbMRkwFwYK
KwYBBAGC2ksvAQwJNDQ5NDcuNC4xME4wEAYHKoZIzj0CAQYFK4EEACEDOgAERbiP
RTb8x/eav43juNzWZLId2Wl5TzmTsG5iRf+CiB+rn+TXnuUbWDIuIi/kYs3USANm
LUyLxH+jNDAyMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MA8GA1Ud
DgQIBAaC3xMBAgEwCgYIKoZIzj0EAwIDQQAwPgIdAMebuq7759hyFC3hjrVUEaXk
2TewRlXg+ohJvFoCHQCTMjnYvLIvTCqF3gZm38+h1iShEgMfMT522d60
`, "\n", ""))
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	caID, err := getCAID(cert)
	if err != nil {
		t.Fatal(err)
	}

	expected := "44947.4.1"
	if caID != expected {
		t.Errorf("getCAID(): got %s, want %s", caID, expected)
	}
}
