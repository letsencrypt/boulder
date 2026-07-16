//go:build go1.27

package mtca

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/borp"

	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/mtca/proto"
	"github.com/letsencrypt/boulder/test/vars"
	"github.com/letsencrypt/boulder/trees/cosigned"
)

// setup returns a working mtca plus a cleanup function, or an error.
func setup() (*mtca, func(), error) {
	issuer, err := issuance.LoadIssuer(issuance.IssuerConfig{
		Profiles:   []string{},
		IssuerURL:  "http://ignored.letsencrypt.org",
		CRLURLBase: "http://ignored.letsencrypt.org/",
		CRLShards:  1,
		Location: issuance.IssuerLoc{
			File:     "../test/certs/mtpki/mtca1.key.pem",
			CertFile: "../test/certs/mtpki/mtca1.cert.pem",
		},
	}, clock.NewFake())
	if err != nil {
		return nil, nil, err
	}

	db, err := sql.Open("mysql", vars.DBConnMTCMeta_44947_4_1_0_44FullPerms)
	if err != nil {
		return nil, nil, err
	}
	dbMap := &borp.DbMap{Db: db, Dialect: borp.MySQLDialect{}}
	truncateTables(db)

	logger := blog.NewMock()

	mtca, err := New(issuer, 100*time.Millisecond, dbMap, logger)
	if err != nil {
		return nil, nil, err
	}

	mtca.InitLog(context.Background())

	cleanup := func() {
		truncateTables(db)
	}

	return mtca, cleanup, nil
}

func TestPool(t *testing.T) {
	p := &pool{maxSize: 20}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Go(func() {
			err := p.append(entry{})
			if err != nil {
				t.Errorf("appending entry: %s", err)
			}
		})
	}
	wg.Wait()

	err := p.append(entry{})
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

func truncateTables(db *sql.DB) {
	db.Exec("TRUNCATE TABLE checkpoints")
	db.Exec("TRUNCATE TABLE latestCheckpoint")
}

func TestSequence(t *testing.T) {
	mtca, cleanup, err := setup()
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
	type result struct {
		*proto.IssueResponse
		error
	}
	ch := make(chan result)
	for i := 0; i < 5; i++ {
		go func() {
			resp, err := mtca.Issue(t.Context(), &proto.IssueRequest{
				Pubkey: []byte("abc"),
				Identifiers: []*corepb.Identifier{
					{Type: "dns", Value: "example.com"},
				},
				Profile: "mtcExample",
			})
			ch <- result{IssueResponse: resp, error: err}
		}()
	}
	// Issue blocks until sequencing, so wait for all five to be pooled.
	for mtca.pool.len() < 5 {
		time.Sleep(time.Millisecond)
	}
	// With the pool full, a sixth request should fail.
	_, err = mtca.Issue(t.Context(), &proto.IssueRequest{Pubkey: []byte("abc")})
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
	// Fake publication
	latest, err := mtca.latestCheckpoint(t.Context())
	if err != nil {
		t.Fatalf("getting latest: %s", err)
	}
	latest.MirrorID = "fake"
	latest.MirrorSignature = []byte("fake")
	_, err = mtca.db.Update(t.Context(), latest)
	if err != nil {
		t.Fatalf("updating checkpoint with fake mirror signature: %s", err)
	}
	// Now sequencing should succeed.
	err = mtca.sequence(t.Context())
	if err != nil {
		t.Fatalf("sequencing with waiting entries: %s", err)
	}
	// The five requests should now be unblocked and return results.
	seenIDs := map[int64]bool{}
	for i := 0; i < 5; i++ {
		res := <-ch
		if res.error != nil {
			t.Errorf("Issue: %s", res.error)
			continue
		}
		if res.MtcEntryIndex < 1 || res.MtcEntryIndex > 5 || seenIDs[res.MtcEntryIndex] {
			t.Errorf("entryIndex %d out of range or seen twice", res.MtcEntryIndex)
		}
		seenIDs[res.MtcEntryIndex] = true
	}
	// Lastly, verify the resulting checkpoint is valid.
	latest, err = mtca.latestCheckpoint(t.Context())
	if err != nil {
		t.Fatalf("getting latest: %s", err)
	}
	verify(t, mtca, latest)
}

func TestInitLog(t *testing.T) {
	mtca, cleanup, err := setup()
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

	verify(t, mtca, latest)
}

func verify(t *testing.T, mtca *mtca, checkpoint *checkpoint) {
	t.Helper()
	message := cosigned.Message{
		CosignerName: fmt.Sprintf("oid/1.3.6.1.4.1.%s", mtca.mtcaID),
		Timestamp:    0,
		LogOrigin:    fmt.Sprintf("oid/1.3.6.1.4.1.%s", mtca.mtcLogID()),
		Start:        0,
		End:          uint64(checkpoint.TreeSize),
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

func TestGetMTCAID(t *testing.T) {
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
	mtcaID, err := getMTCAID(cert)
	if err != nil {
		t.Fatal(err)
	}

	expected := "44947.4.1"
	if mtcaID != expected {
		t.Errorf("getMTCAID(): got %s, want %s", mtcaID, expected)
	}
}
