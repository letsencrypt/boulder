//go:build integration

package integration

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"golang.org/x/mod/sumdb/note"

	"github.com/letsencrypt/boulder/test/vars"
	"github.com/letsencrypt/boulder/trees/checkpoint"
	"github.com/letsencrypt/boulder/trees/tilestore"
	"github.com/letsencrypt/boulder/trees/tilestore/s3"
)

const (
	mtpubLogID      = "44947.4.1.0.44"
	mtpubOrigin     = "example.com/log"
	mtpubMirrorName = "mirror.test/m1"
	mtpubMirrorURL  = "http://localhost:4700"
	// mtpubMinIOEndpoint and mtpubBucket locate the source log's tiles in MinIO,
	// where the boulder-mtpublisher reads them from. They match its config.
	mtpubMinIOEndpoint = "http://boulder-minio:9000"
	mtpubBucket        = "boulder-mtc-tiles"
	// mtpubLogSigner is the note signer whose verifier is configured in
	// tlog-mirror-test-srv.json, so the mirror accepts the source log's
	// checkpoint.
	mtpubLogSigner = "PRIVATE+KEY+example.com/log+b7d49da7+AbzWSkBJsF9IEj/YmHbWnbYBBuJtUKpIsFL5sCss7vI9"
	// mtpubCosigSize is the length of an ML-DSA-44 timestamped_signature: an
	// 8-byte timestamp followed by the 2420-byte signature.
	mtpubCosigSize = 8 + 2420
)

// minioSourceStore returns a tilestore over the MinIO bucket the publisher reads
// its source log from, using the MinIO root credentials.
func minioSourceStore(t *testing.T) *tilestore.Store {
	t.Helper()
	awsConfig, err := awsconfig.LoadDefaultConfig(t.Context(),
		awsconfig.WithRegion("us-west-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("minioadmin", "minioadmin", "")),
	)
	if err != nil {
		t.Fatalf("loading AWS config: %s", err)
	}
	client := awss3.NewFromConfig(awsConfig,
		awss3.WithEndpointResolver(awss3.EndpointResolverFromURL(mtpubMinIOEndpoint)),
		func(o *awss3.Options) { o.UsePathStyle = true },
	)
	return tilestore.New(s3.New(client, mtpubBucket), mtpubOrigin)
}

// TestMTPublisherCosignsCheckpoint exercises the live boulder-mtpublisher and
// tlog-mirror-test-srv end to end: it writes a deterministic source log the
// publisher mirrors, inserts a checkpoint for it to act on, and confirms the
// publisher records a mirror cosignature that the mirror also serves.
//
// The source log is deterministic, so a mirror that already holds it from a
// prior run stays consistent; changing the entries requires resetting the
// mirror's volume (docker compose down -v).
func TestMTPublisherCosignsCheckpoint(t *testing.T) {
	// The mtpublisher and tlog-mirror-test-srv only run in config-next, where the
	// binaries are built with gotip (go1.27, for crypto/mldsa).
	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		t.Skip("mtpublisher and tlog-mirror-test-srv only run in config-next")
	}

	// Write the source log the publisher will mirror (entries plus a log-signed
	// checkpoint) into the MinIO bucket it reads from. The log is deterministic,
	// so when the bucket already holds it from a prior run we reuse that tree
	// rather than re-appending, which the size guard would reject. Resetting the
	// log means pruning the minio-data volume (docker compose down -v).
	src := minioSourceStore(t)
	tree, err := src.Tree(t.Context())
	if err != nil {
		t.Fatalf("reading source tree: %s", err)
	}
	if tree.N == 0 {
		entries := make([][]byte, 300)
		for i := range entries {
			entries[i] = fmt.Appendf(nil, "entry-%d", i)
		}
		tree, err = src.Append(t.Context(), 0, entries)
		if err != nil {
			t.Fatalf("appending source log: %s", err)
		}
	}
	signer, err := note.NewSigner(mtpubLogSigner)
	if err != nil {
		t.Fatalf("NewSigner: %s", err)
	}
	body := checkpoint.Checkpoint{Origin: mtpubOrigin, Tree: tree}.String()
	signed, err := note.Sign(&note.Note{Text: body}, signer)
	if err != nil {
		t.Fatalf("signing checkpoint: %s", err)
	}
	err = src.WriteCheckpoint(t.Context(), signed)
	if err != nil {
		t.Fatalf("writing source checkpoint: %s", err)
	}

	db, err := sql.Open("mysql", vars.DBConnMTCMeta_44947_4_1_0_44FullPerms)
	if err != nil {
		t.Fatalf("opening MTC meta DB: %s", err)
	}
	defer db.Close()

	// Start from a clean slate so our row is the latest, and clean up after.
	_, err = db.ExecContext(t.Context(), "DELETE FROM checkpoints WHERE mtcLogID = ?", mtpubLogID)
	if err != nil {
		t.Fatalf("clearing checkpoints: %s", err)
	}
	t.Cleanup(func() {
		_, err := db.ExecContext(context.Background(), "DELETE FROM checkpoints WHERE mtcLogID = ?", mtpubLogID)
		if err != nil {
			t.Logf("cleaning up checkpoints: %s", err)
		}
	})

	_, err = db.ExecContext(t.Context(),
		"INSERT INTO checkpoints (mtcLogID, mtcaSignature, treeSize, rootHash) VALUES (?, ?, ?, ?)",
		mtpubLogID, []byte("mtca-signature"), tree.N, tree.Hash[:])
	if err != nil {
		t.Fatalf("inserting checkpoint: %s", err)
	}

	// The publisher polls; wait for it to mirror the log and record the
	// cosig.
	var cosig []byte
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		err = db.QueryRowContext(t.Context(),
			"SELECT mirrorSignature FROM checkpoints WHERE mtcLogID = ? AND treeSize = ?", mtpubLogID, tree.N).Scan(&cosig)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("querying cosignature: %s", err)
		}
		if len(cosig) > 0 {
			break
		}
		time.Sleep(time.Second)
	}
	if len(cosig) != mtpubCosigSize {
		t.Fatalf("recorded mirrorSignature is %d bytes, want %d; the publisher did not cosign in time", len(cosig), mtpubCosigSize)
	}

	// The mirror's served monitoring checkpoint must carry the mirror cosignature
	// line, confirming the test-srv mirrored and cosigned the same log.
	resp, err := http.Get(mtpubMirrorURL + "/" + url.PathEscape(mtpubOrigin) + "/checkpoint")
	if err != nil {
		t.Fatalf("GET served checkpoint: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET served checkpoint status = %d, want 200", resp.StatusCode)
	}
	served, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading served checkpoint: %s", err)
	}
	if !strings.Contains(string(served), "— "+mtpubMirrorName+" ") {
		t.Errorf("served checkpoint lacks a %q cosignature line:\n%s", mtpubMirrorName, served)
	}
}
