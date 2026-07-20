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
	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/trees/entry"
	"github.com/letsencrypt/boulder/trees/subtree"
)

var ErrFileExists = errors.New("file exists")

// simpleS3 matches the subset of the s3.Client interface which we use, to allow
// simpler mocking in tests.
type simpleS3 interface {
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	Bucket() string
}

// Frontier contains all the tiles on the right edge of the tree,
// partial and full. It keeps track of which tiles have been
// modified and need to be written to storage.
//
// When we need to append a hash to a level with a full tile, the
// full tile gets moved into a holding list of tiles that are not
// on the right edge but need to be written.
type Frontier struct {
	// The rightmost hash tiles in the tree, ordered from level 0
	// (leaf hashes) to level N (containing the root hash).
	// Will be empty only on an empty tree (i.e. NewFrontier())
	hashesTiles []*hashesTile

	// entryTile contains the rightmost tile in the entries layer.
	// Will be empty only on an empty tree (i.e. NewFrontier())
	entryTile *entryTile

	// This level of hashes and all below it need writing to storage
	// (including entries).
	//
	// -1 means nothing needs writing.
	dirtyLevel int

	// Tiles pushed off the frontier are stored here to be written. No particular order.
	fullHashesTiles []*hashesTile
	fullEntryTiles  []*entryTile

	treeSize int64
}

// hashesTile represents a tile containing hashes.
type hashesTile struct {
	// Note we don't bother setting H because it's not encoded
	// in paths for tlog-tiles.
	coords tlog.Tile
	data   []tlog.Hash
}

// entryTile represent a tile containing entries.
type entryTile struct {
	coords tlog.Tile
	data   []byte
}

// NewFrontier returns a frontier object representing an empty tree,
// suitable for initializing a tree for the first time.
func NewFrontier() *Frontier {
	return &Frontier{
		entryTile: &entryTile{
			coords: tlog.Tile{
				L: -1, // entries layer is represented as -1.
			},
		},
		dirtyLevel: -1,
	}
}

// Load loads the current frontier from storage, given the current tree size.
func Load(ctx context.Context, s3c simpleS3, treeSize int64, prefix string) (*Frontier, error) {
	if treeSize == 0 {
		return nil, fmt.Errorf("can't load an empty tree")
	}

	tileIndex := treeSize / 256
	width := int(treeSize % 256)
	// If the tile would be empty get the full tile to its left instead.
	if width == 0 {
		tileIndex--
		width = 256
	}

	coords := tlog.Tile{
		L: -1, // entries layer is represented as -1.
		N: tileIndex,
		W: width,
	}

	entryData, err := getTile(ctx, s3c, coords, prefix)
	if err != nil {
		return nil, err
	}

	br := entry.NewBundleReader(entryData)
	var entriesCount int
	for ; ; entriesCount++ {
		_, _, err = br.ReadEntry()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("parsing entries: %s", err)
		}
	}
	if entriesCount != coords.W {
		return nil, fmt.Errorf("reading entries from %q: got %d entries, want %d",
			tilePath(coords), entriesCount, coords.W)
	}

	entryTile := &entryTile{
		coords: coords,
		data:   entryData,
	}

	var hashesTiles []*hashesTile
	// Iterate up the tree. layerSize is the number of hashes (not tiles)
	// in a layer.
	for layerSize := treeSize; layerSize > 0; layerSize /= 256 {
		level := len(hashesTiles)
		tileIndex = layerSize / 256

		width := int(layerSize % 256)
		// If the tile would be empty get the full tile to its left instead.
		if width == 0 {
			tileIndex--
			width = 256
		}

		coords := tlog.Tile{
			L: level,
			N: tileIndex,
			W: width,
		}

		body, err := getTile(ctx, s3c, coords, prefix)
		if err != nil {
			return nil, err
		}

		if len(body) != width*tlog.HashSize {
			return nil, fmt.Errorf("%q: got %d bytes, expected %d",
				tilePath(coords), len(body), width*tlog.HashSize)
		}

		var data []tlog.Hash
		for i := 0; i < width; i++ {
			var hash tlog.Hash
			copy(hash[:], body[:tlog.HashSize])
			data = append(data, hash)
			body = body[tlog.HashSize:]
		}

		hashesTiles = append(hashesTiles, &hashesTile{
			coords: coords,
			data:   data,
		})
	}

	return &Frontier{
		hashesTiles: hashesTiles,
		entryTile:   entryTile,
		treeSize:    treeSize,
		dirtyLevel:  -1,
	}, nil
}

// TreeSize returns the current tree size.
func (f *Frontier) TreeSize() int64 {
	return f.treeSize
}

// AppendEntry appends a single MTCLogEntry to the entries tile and a
// corresponding hash to the level-0 hashes tile, updating any higher
// levels as needed.
func (f *Frontier) AppendEntry(mtcle *entry.MTCLogEntry) error {
	mtcleBytes, err := mtcle.Marshal()
	if err != nil {
		return err
	}

	// TODO: this serializes the MTCLogEntry again, which is a bit silly.
	// Refactor?
	bb := entry.NewBundleBuilder(nil)
	bb.Add(mtcle)
	bundleBytes, err := bb.Bytes()
	if err != nil {
		return err
	}

	if f.entryTile.coords.W == 256 {
		// Existing tile is full. Queue it for writing (if it's dirty).
		if f.dirtyLevel >= 0 {
			f.fullEntryTiles = append(f.fullEntryTiles, f.entryTile)
		}
		f.entryTile = &entryTile{
			coords: tlog.Tile{
				L: -1, // entries layer is represented as -1.
				N: f.treeSize / 256,
			},
		}
	}

	f.entryTile.data = append(f.entryTile.data, bundleBytes...)
	f.entryTile.coords.W++

	f.appendHash(tlog.RecordHash(mtcleBytes), 0)

	f.treeSize++

	return nil
}

// appendHash appends a single hash to the given level, updating any levels
// above as needed.
//
// Panics if asked to append more than one level above the top of the tree
// (in other words, if level > len(hashesTiles)).
func (f *Frontier) appendHash(val tlog.Hash, level int) {
	if level == len(f.hashesTiles) {
		// Add a level to the top of the tree by expanding hashesTiles.
		f.hashesTiles = append(f.hashesTiles, &hashesTile{
			coords: tlog.Tile{L: level},
		})
	} else if level > len(f.hashesTiles) {
		panic(fmt.Sprintf("tried to write a level %d tile to a frontier with %d levels",
			level, len(f.hashesTiles)))
	}

	currentTile := f.hashesTiles[level]
	if currentTile.coords.W != 256 {
		currentTile.data = append(currentTile.data, val)
		currentTile.coords.W++

		if currentTile.coords.W == 256 {
			// We finished a tile. Now we get to append that tile's hash
			// to the tile above it.
			fullTileHash := subtree.MTH(currentTile.data)
			f.appendHash(fullTileHash, level+1)
		}
	} else {
		// Move the full tile to the holding area and create
		// a new one with one entry. Only if the full tile
		// needs to be written.
		if f.dirtyLevel >= level {
			f.fullHashesTiles = append(f.fullHashesTiles, currentTile)
		}

		newCoords := currentTile.coords
		newCoords.N++
		newCoords.W = 1

		f.hashesTiles[level] = &hashesTile{
			coords: newCoords,
			data:   []tlog.Hash{val},
		}
	}

	f.dirtyLevel = max(f.dirtyLevel, level)
}

// Flush writes all dirty tiles to storage and clears their dirty status.
//
// If it errors partway, dirty status is not reset but subsequent flushes
// will likely fail (duplicate writes).
//
// Errors if the tree is empty (i.e. NewFrontier() without appending any entries).
func (f *Frontier) Flush(ctx context.Context, s3c simpleS3, prefix string) error {
	if f.treeSize == 0 {
		return fmt.Errorf("an empty tree has nothing to write")
	}

	if f.dirtyLevel == -1 {
		// Nothing's dirty!
		return nil
	}

	for _, t := range f.fullEntryTiles {
		err := writeTile(ctx, s3c, prefix, t.coords, t.data, true)
		if err != nil {
			return err
		}
	}

	err := writeTile(ctx, s3c, prefix, f.entryTile.coords, f.entryTile.data, true)
	if err != nil {
		return err
	}

	dirtyHashTiles := append(f.fullHashesTiles, f.hashesTiles[:f.dirtyLevel+1]...)
	for _, dt := range dirtyHashTiles {
		if len(dt.data) == 0 {
			return fmt.Errorf("shouldn't happen: empty hash tile %v", dt.coords)
		}
		// Transform our slice of 32-byte arrays into a contiguous byte slice.
		body := make([]byte, 0, len(dt.data)*tlog.HashSize)
		for i := range len(dt.data) {
			body = append(body, dt.data[i][:]...)
		}
		err := writeTile(ctx, s3c, prefix, dt.coords, body, false)
		if err != nil {
			return err
		}
	}

	f.fullHashesTiles = nil
	f.fullEntryTiles = nil
	f.dirtyLevel = -1
	return nil
}

// writeTile writes a single tile. Handles hash tiles and entry tiles, using coords.L to distinguish.
//
// If compress is true, compresses the data before storing.
func writeTile(
	ctx context.Context,
	s3c simpleS3,
	prefix string,
	coords tlog.Tile,
	body []byte,
	compress bool,
) error {
	path := prefix + tilePath(coords)
	if len(body) == 0 {
		return fmt.Errorf("shouldn't happen: attempted to write empty tile to %q", path)
	}

	var contentEncoding *string
	if compress {
		gzipStr := "gzip"
		contentEncoding = &gzipStr
		var buf bytes.Buffer
		gzipWriter := gzip.NewWriter(&buf)
		_, err := gzipWriter.Write(body)
		if err != nil {
			return err
		}

		err = gzipWriter.Close()
		if err != nil {
			return err
		}

		body = buf.Bytes()
	}

	contentType := "application/octet-stream"
	cacheControl := "public, max-age=604800, immutable"
	star := "*"

	bucket := s3c.Bucket()
	_, err := s3c.PutObject(ctx, &s3.PutObjectInput{
		Bucket:          &bucket,
		Key:             &path,
		ContentEncoding: contentEncoding,
		ContentType:     &contentType,
		CacheControl:    &cacheControl,
		Body:            bytes.NewReader(body),
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
			return fmt.Errorf("writing s3://%s/%s: %w", s3c.Bucket(), path, ErrFileExists)
		}
		return fmt.Errorf("writing s3://%s/%s: %w", s3c.Bucket(), path, err)
	}
	return nil
}

// tilePath returns a  tile path like tile/0/x001/x234/067.p/23.
//
// tileIndex is the index of a tile within a level, or in other words an
// entry index divided by 256.
//
// If tileLevel is -1, the path starts with tile/entries/ instead of tile/L.
//
// Produces invalid results when treeSize is 0 or if the tileIndex is
// beyond the treeSize.
//
// Note: this is similar to tlog.Tile.Path(), but Path() uses "tile/" and "tile/<H>/data/"
// where we need "tile/" and "tile/entries/" (and don't use <H>).
//
// https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md
func tilePath(coords tlog.Tile) string {
	var out strings.Builder
	if coords.L == -1 {
		out.WriteString("tile/entries/")
	} else {
		fmt.Fprintf(&out, "tile/%d/", coords.L)
	}

	tileIndexString := fmt.Sprintf("%d", coords.N)
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

	if coords.W != 256 {
		// We're at the right edge and the last tile is partial.
		fmt.Fprintf(&out, ".p/%d", coords.W)
	}

	return out.String()
}

func getTile(ctx context.Context, s3c simpleS3, coords tlog.Tile, prefix string) ([]byte, error) {
	path := prefix + tilePath(coords)
	bucket := s3c.Bucket()
	resp, err := s3c.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &path,
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.ContentEncoding != nil && *resp.ContentEncoding == "gzip" {
		gzipReader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}

		decompressed, err := io.ReadAll(gzipReader)
		if err != nil {
			return nil, err
		}

		err = gzipReader.Close()
		if err != nil {
			return nil, err
		}
		return decompressed, nil
	}

	return body, nil

}
