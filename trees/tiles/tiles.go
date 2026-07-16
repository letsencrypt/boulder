package tiles

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/letsencrypt/boulder/trees/entry"
)

// simpleS3 matches the subset of the s3.Client interface which we use, to allow
// simpler mocking in tests.
type simpleS3 interface {
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	Bucket() string
}

// N returns the encoding of a tile index described at
// https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md#merkle-tree
//
// Example: N(1234067) = "x001/x234/067"
func N(tileIndex uint64) string {
	tileIndexString := fmt.Sprintf("%d", tileIndex)
	for len(tileIndexString)%3 != 0 {
		tileIndexString = "0" + tileIndexString
	}

	var out strings.Builder

	for remaining := tileIndexString; len(remaining) != 0; {
		var chunk string
		remaining, chunk = remaining[3:], remaining[:3]
		// Slash between path componenets, not at the start.
		if out.Len() > 0 {
			out.WriteString("/")
		}
		// "x" for each path component but the last.
		if len(remaining) > 0 {
			out.WriteString("x")
		}
		out.WriteString(chunk)
	}

	return out.String()
}

func GetEntry(ctx context.Context,
	s3c simpleS3,
	index, treeSize int64,
) (entry.MerkleTreeCertEntry, error) {
	tileIndex := index / 256
	tileOffset := index % 256

	path := fmt.Sprintf("tile/entries/%s", N(uint64(tileIndex)))
	if treeSize/256 == tileIndex && treeSize%256 != 0 {
		path = path + fmt.Sprintf(".p/%d", treeSize%256)
	}
	bucket := s3c.Bucket()
	resp, err := s3c.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &path,
	})
	if err != nil {
		return entry.MerkleTreeCertEntry{}, err
	}

	gzipReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return entry.MerkleTreeCertEntry{}, err
	}
	br := entry.NewBundleReader(gzipReader)
	for i := range tileOffset + 1 {
		mtce, _, err := br.Read()
		if err != nil {
			return entry.MerkleTreeCertEntry{}, err
		}
		if i == tileOffset {
			return mtce, nil
		}
	}

	return entry.MerkleTreeCertEntry{}, fmt.Errorf("entry %d not found in tile %q", tileOffset, path)
}

func WriteEntries(ctx context.Context,
	s3c simpleS3,
	startingIndex int64,
	entries []entry.MerkleTreeCertEntry,
) error {
	for len(entries) > 0 {
		partialWidth := startingIndex % 256
		remaining := int(256 - partialWidth)
		chunkSize := min(remaining, len(entries))
		var chunk []entry.MerkleTreeCertEntry
		chunk, entries = entries[:chunkSize], entries[chunkSize:]
		err := writeEntries(ctx, s3c, startingIndex, chunk)
		if err != nil {
			return err
		}
		startingIndex += int64(len(chunk))
	}
	return nil
}

// entries must be at most 256 long.
func writeEntries(ctx context.Context,
	s3c simpleS3,
	startingIndex int64,
	entries []entry.MerkleTreeCertEntry) error {
	if len(entries) > 256 {
		return fmt.Errorf("shouldn't happen: len(entries) = %d", len(entries))
	}
	// partialTileBytes wil be empty if there is no partial tile to append to.
	partialTileBytes, tileEntryCount, err := readPartial(ctx, startingIndex, s3c)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	gzipWriter, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return err
	}

	_, err = gzipWriter.Write(partialTileBytes)
	if err != nil {
		return err
	}

	bundleWriter := entry.NewBundleWriter(gzipWriter)

	for _, e := range entries {
		err = bundleWriter.Write(e)
		if err != nil {
			return err
		}
		tileEntryCount++
		if tileEntryCount > 256 {
			return fmt.Errorf("shouldn't happen: too many entries for a tile")
		}
	}
	err = bundleWriter.Close()
	if err != nil {
		return err
	}

	tileIndex := startingIndex / 256
	filename := fmt.Sprintf("tile/entries/%s", N(uint64(tileIndex)))
	if tileEntryCount != 256 {
		filename = filename + fmt.Sprintf(".p/%d", tileEntryCount)
	}
	contentEncoding := "gzip"
	contentType := "application/octet-stream"
	cacheControl := "public, max-age=604800, immutable"
	star := "*"

	bucket := s3c.Bucket()
	_, err = s3c.PutObject(ctx, &s3.PutObjectInput{
		Bucket:          &bucket,
		Key:             &filename,
		ContentEncoding: &contentEncoding,
		ContentType:     &contentType,
		CacheControl:    &cacheControl,
		Body:            bytes.NewReader(buf.Bytes()),
		// Error if the file exists
		IfNoneMatch: &star,
	})
	if err != nil {
		respErr, ok := errors.AsType[*awshttp.ResponseError](err)
		if ok && respErr.HTTPStatusCode() == http.StatusPreconditionFailed {
			return fmt.Errorf("writing s3://%s/%s: file exists", s3c.Bucket(), filename)
		}
		return fmt.Errorf("writing s3://%s/%s: %v", s3c.Bucket(), filename, err)
	}

	return nil
}

// readPartial returns the decompressed bytes of the existing partial tile that contains
// the entry at `startingIndex`, along with the number of entries in that tile.
//
// If startingIndex % 256 == 0, returns nil, 0, nil.
func readPartial(ctx context.Context, startingIndex int64, s3c simpleS3) ([]byte, int64, error) {
	partialTileIndex, partialWidth := startingIndex/256, startingIndex%256
	if partialWidth == 0 {
		return nil, 0, nil
	}
	path := fmt.Sprintf("tile/entries/%s.p/%d", N(uint64(partialTileIndex)), partialWidth)
	bucket := s3c.Bucket()
	resp, err := s3c.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &path,
	})
	if err != nil {
		return nil, 0, err
	}
	partial, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}

	// Double check that it has the right number of entries.
	readBuf := bytes.NewReader(partial)
	gzipReader, err := gzip.NewReader(readBuf)
	if err != nil {
		return nil, 0, err
	}

	decompressed, err := io.ReadAll(gzipReader)
	if err != nil {
		return nil, 0, err
	}

	br := entry.NewBundleReader(bytes.NewReader(decompressed))
	for range partialWidth {
		_, _, err := br.Read()
		if err != nil {
			return nil, 0, err
		}
	}
	if readBuf.Len() > 0 {
		return nil, 0, fmt.Errorf("after reading %d entries from %q: %d excess bytes",
			partialWidth, path, readBuf.Len())
	}
	return decompressed, partialWidth, nil
}
