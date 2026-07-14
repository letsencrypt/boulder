//go:build go1.27

package mtca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/borp"

	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/mtca/proto"
	"github.com/letsencrypt/boulder/test/vars"
	"github.com/letsencrypt/boulder/trees/cosigned"
)

func TestPool(t *testing.T) {
	p := &pool{maxSize: 20}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Go(func() {
			err := p.append(pendingEntry{})
			if err != nil {
				t.Fatal(err)
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

// setup returns a working mtca plus a cleanup function, or an error.
func setup() (*mtca, func(), error) {
	issuer, err := issuance.LoadIssuer(issuance.IssuerConfig{
		Profiles:   []string{"required to be active"},
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
	clk := clock.NewFake()

	profile, err := issuance.NewProfile(issuance.ProfileConfig{
		OmitCommonName:      true,
		OmitKeyEncipherment: true,
		OmitClientAuth:      true,
		OmitSKID:            true,
		// TODO:
		// OmitCT: true,
		LintConfig: "",
		IgnoredLints: []string{
			"w_ext_subject_key_identifier_missing_sub_cert",
			"w_ct_sct_policy_count_unsatisfied",
			"e_signature_algorithm_not_supported",
		},
	})
	if err != nil {
		return nil, nil, err
	}

	s3c := newSimpleS3()

	mtca, err := New(issuer, profile, dbMap, s3c, logger, clk)
	if err != nil {
		return nil, nil, err
	}

	mtca.InitLog(context.Background())

	cleanup := func() {
		truncateTables(db)
	}

	return mtca, cleanup, nil
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

	mtca.pool.append(pendingEntry{ch: make(chan int64, 1)})

	err = mtca.sequence(t.Context())
	if err == nil {
		t.Fatalf("sequencing with an unready checkpoint: got nil error, want error")
	}
	if !strings.Contains(err.Error(), "not ready") {
		t.Errorf("sequencing with an unready checkpoint: expected 'not ready', got %q", err)
	}

	mtca.pool.take()

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

	err = mtca.sequence(t.Context())
	if err != nil {
		t.Fatalf("sequencing with ready checkpoint and empty pool: %s", err)
	}

	mtca.pool.maxSize = 5

	key, err := ecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		t.Fatalf("generating key: %s", err)
	}
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatalf("marshaling pubkey: %s", err)
	}

	type result struct {
		*proto.IssueResponse
		error
	}
	ch := make(chan result)
	for i := 0; i < 6; i++ {
		go func() {
			resp, err := mtca.Issue(t.Context(), &proto.IssueRequest{
				Pubkey: pubkeyBytes,
				Identifiers: []*corepb.Identifier{
					{Type: "dns", Value: "example.com"},
				},
				Profile: "mtcExample",
			})
			ch <- result{IssueResponse: resp, error: err}
		}()
	}

	err = mtca.sequence(t.Context())
	if err != nil {
		t.Fatalf("sequencing with waiting entries: %s", err)
	}

	seenIDs := map[int64]bool{}
	var seenError error
	for i := 0; i < 6; i++ {
		res := <-ch
		if res.error != nil {
			if seenError != nil {
				t.Errorf("too many errors: %s", res.error)
			}
			seenError = res.error
			continue
		}
		if seenIDs[res.MtcEntryIndex] {
			t.Errorf("entryIndex %d seen twice", res.MtcEntryIndex)
		}
		seenIDs[res.MtcEntryIndex] = true
	}

	if seenError == nil {
		t.Errorf("putting 6 entries in a pool of size 5: expected error, got none")
	}
	if !strings.Contains(seenError.Error(), "pool is full") {
		t.Errorf("putting 6 entries in a pool of size 5: expected 'pool is full', got %q", seenError)
	}

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

type simpleS3 struct {
	objects map[string][]byte
}

func newSimpleS3() *simpleS3 {
	return &simpleS3{make(map[string][]byte)}
}

func (s *simpleS3) Bucket() string {
	return "fake bucket"
}

func (s *simpleS3) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if params.Key == nil {
		return nil, fmt.Errorf("nil key")
	}
	b, err := io.ReadAll(params.Body)
	if err != nil {
		return nil, err
	}
	s.objects[*params.Key] = b
	return nil, nil
}

func (s *simpleS3) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if params.Key == nil {
		return nil, fmt.Errorf("nil key")
	}
	obj, ok := s.objects[*params.Key]
	if !ok {
		return nil, fmt.Errorf("object not found")
	}

	return &s3.GetObjectOutput{
		Body: io.NopCloser(bytes.NewReader(obj)),
	}, nil
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
	mtcaID, err := getMTCAID(cert)
	if err != nil {
		t.Fatal(err)
	}

	expected := "44947.4.1"
	if mtcaID != expected {
		t.Errorf("getMTCAID(): got %s, want %s", mtcaID, expected)
	}
}
