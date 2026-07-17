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

var ErrFileExists = errors.New("file exists")

// simpleS3 matches the subset of the s3.Client interface which we use, to allow
// simpler mocking in tests.
type simpleS3 interface {
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	Bucket() string
}

// tilePath returns an entry tile path like tile/entries/x001/x234/067.p/23.
//
// tileIndex is the index of a tile within a level, or in other words an
// entry index divided by 256.
//
// Produces invalid results when treeSize is 0 or if tileIndex * 256 >= treeSize.
func tilePath(tileIndex, treeSize int64) string {
	var out strings.Builder
	out.WriteString("tile/entries/")
	tileIndexString := fmt.Sprintf("%d", tileIndex)
	for len(tileIndexString)%3 != 0 {
		tileIndexString = "0" + tileIndexString
	}

	// Construct the 3-digit-chunked form of tileIndex.
	// https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md#merkle-tree
	//
	// Example: N(1234067) = "x001/x234/067"
	for remaining := tileIndexString; len(remaining) != 0; {
		var chunk string
		remaining, chunk = remaining[3:], remaining[:3]
		// "x" for each path component but the last.
		if len(remaining) > 0 {
			out.WriteString("x")
		}
		out.WriteString(chunk)
		if len(remaining) >= 3 {
			out.WriteString("/")
		}
	}

	if treeSize/256 == tileIndex && treeSize%256 != 0 {
		// We're at the right edge and the last tile is partial.
		fmt.Fprintf(&out, ".p/%d", treeSize%256)
	}

	return out.String()
}

// For a tile at `tileIndex` in a tree of size `treeSize`, return
// the width of that tile if it's partial. Otherwise return zero.
func partialWidth(tileIndex, treeSize int64) int {
	if treeSize/256 == tileIndex && treeSize%256 != 0 {
		return int(treeSize % 256)
	}
	return 0
}

func WriteEntries(
	ctx context.Context,
	s3c simpleS3,
	startingIndex int64,
	entries []*entry.MTCLogEntry,
) error {
	for len(entries) > 0 {
		partialWidth := startingIndex % 256
		remaining := int(256 - partialWidth)
		chunkSize := min(remaining, len(entries))
		var chunk []*entry.MTCLogEntry
		chunk, entries = entries[:chunkSize], entries[chunkSize:]
		err := writeTile(ctx, s3c, startingIndex, chunk)
		if err != nil {
			return err
		}
		startingIndex += int64(len(chunk))
	}
	return nil
}

// writeTile writes one tile, appending entries from startingIndex.
//
// If there's an existing partial tile, it reads the existing bytes,
// checks for the correct number of entries, appends to those, and
// writes the result.
//
// Errors if the combination of startingIndex and len(entries) would
// cross a tile boundary.
//
// If the tile to be written already exists in S3, returns an error
// that wraps ErrTileExists.
func writeTile(ctx context.Context,
	s3c simpleS3,
	startingIndex int64,
	entries []*entry.MTCLogEntry) error {
	partialWidth := startingIndex % 256

	if len(entries)+int(partialWidth) > 256 {
		return fmt.Errorf("shouldn't happen: len(entries) = %d, partialWidth = %d",
			len(entries), partialWidth)
	}

	var partialTileBytes []byte
	if partialWidth != 0 {
		var mtcles []*entry.MTCLogEntry
		mtcles, body, err := GetEntries(ctx, s3c, startingIndex/256, startingIndex)
		if err != nil {
			return err
		}
		if len(mtcles) != int(partialWidth) {
			return fmt.Errorf("reading partial tile: got %d entries, want %d", len(mtcles), partialWidth)
		}
		partialTileBytes = body
	}

	bundleWriter := entry.NewBundleBuilder(partialTileBytes)

	tileEntryCount := partialWidth
	for _, e := range entries {
		bundleWriter.Add(e)
		tileEntryCount++
		if tileEntryCount > 256 {
			return fmt.Errorf("shouldn't happen: too many entries for a tile")
		}
	}

	tile, err := bundleWriter.Bytes()
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	gzipWriter, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return err
	}

	_, err = gzipWriter.Write(tile)
	if err != nil {
		return err
	}

	err = gzipWriter.Close()
	if err != nil {
		return err
	}

	tileIndex := startingIndex / 256
	newTilePath := tilePath(tileIndex, startingIndex+int64(len(entries)))
	contentEncoding := "gzip"
	contentType := "application/octet-stream"
	cacheControl := "public, max-age=604800, immutable"
	star := "*"

	bucket := s3c.Bucket()
	_, err = s3c.PutObject(ctx, &s3.PutObjectInput{
		Bucket:          &bucket,
		Key:             &newTilePath,
		ContentEncoding: &contentEncoding,
		ContentType:     &contentType,
		CacheControl:    &cacheControl,
		Body:            bytes.NewReader(buf.Bytes()),
		// Error if the file exists
		IfNoneMatch: &star,
	})
	if err != nil {
		respErr, ok := errors.AsType[*awshttp.ResponseError](err)
		// PreconditionFailed, in this case, means our IfNoneMatch: "*"
		// failed, which in turn means the file already existed. By the
		// way the spec is designed, we should never write a tile twice.
		// Partial tiles are written at different paths based on width.
		// https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/http-412-precondition-failed.html
		if ok && respErr.HTTPStatusCode() == http.StatusPreconditionFailed {
			return fmt.Errorf("writing s3://%s/%s: %w", s3c.Bucket(), newTilePath, ErrFileExists)
		}
		return fmt.Errorf("writing s3://%s/%s: %v", s3c.Bucket(), newTilePath, err)
	}

	return nil
}

func GetEntries(
	ctx context.Context,
	s3c simpleS3,
	tileIndex int64,
	treeSize int64,
) ([]*entry.MTCLogEntry, []byte, error) {
	if treeSize == 0 {
		return nil, nil, fmt.Errorf("tree size 0 is invalid")
	}
	path := tilePath(tileIndex, treeSize)
	bucket := s3c.Bucket()
	resp, err := s3c.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &path,
	})
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	partial, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	readBuf := bytes.NewReader(partial)
	gzipReader, err := gzip.NewReader(readBuf)
	if err != nil {
		return nil, nil, err
	}

	decompressed, err := io.ReadAll(gzipReader)
	if err != nil {
		return nil, nil, err
	}

	err = gzipReader.Close()
	if err != nil {
		return nil, nil, err
	}

	br := entry.NewBundleReader(decompressed)
	var entries []*entry.MTCLogEntry
	for {
		entry, _, err := br.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, nil, err
		}
		entries = append(entries, entry)
	}

	expectedEntries := partialWidth(tileIndex, treeSize)
	if expectedEntries == 0 {
		expectedEntries = 256
	}
	if len(entries) != expectedEntries {
		return nil, nil, fmt.Errorf("GetEntries: got %d entries, want %d",
			len(entries), expectedEntries)
	}

	return entries, nil, nil
}
