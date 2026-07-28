// Package tiles implements https://c2sp.org/tlog-tiles.
//
// Entry tiles contain up to 256 MTCLogEntry objects and are stored as compressed entry bundles.
//
// Hash tiles contain up to 256 32-byte SHA-256 hashes, concatenated. The tile represents up to
// 8 layers of the Merkle Tree, but only the bottom-most of those layers is actually stored. Higher
// layers are calculated from the tile contents as needed.
//
// Invariants:
//   - Tiles in storage are never empty.
//   - Tiles in storage are immutable.
//   - A hash is only appended to a tile when it will be permanent. Equivalently: only the hashes
//     of complete subtrees are appended to a tile.
//   - Any hash stored in a level L tile is equal to MTH(c), where c is a list of exactly 256
//     hashes stored in a child tile at level L-1 (for L > 0).
package tiles

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"slices"
	"strings"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/trees/entry"
	"github.com/letsencrypt/boulder/trees/subtree"
)

// ErrTileExists is returned when trying to write a tile that already exists in storage.
var ErrTileExists = errors.New("tile exists")

// simpleS3 matches the subset of the bs3.Client interface which we use, to allow
// simpler mocking in tests.
type simpleS3 interface {
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	Bucket() string
}

// Frontier contains all the tiles on the right edge of the tree,
// which may be partial or empty (but not full). It keeps track
// of which tiles have been modified and need to be written to
// storage.
//
// When a tile becomes full, it gets moved into a holding list of
// tiles that are not on the right edge but need to be written and
// its MTH gets appended to the tile above it.
//
// The zero value of Frontier represents an empty tree. Empty trees
// cannot be loaded or flushed.
//
// Frontier is not safe for concurrent access.
type Frontier struct {
	// The rightmost hash tiles in the tree, ordered from level 0
	// (leaf hashes) to the top of the tree.
	//
	// Will be empty only on an empty tree.
	//
	// Tiles in this list may be empty (coords.W == 0) but never
	// full (coords.W == 256).
	hashesTiles []*hashesTile

	// entryTile contains the rightmost tile in the entries layer.
	// May be empty but never full.
	entryTile *entryTile

	// This level of hashes and all below it need writing to storage
	// (including entries).
	//
	// -1 means nothing needs writing.
	dirtyLevel int

	// Tiles pushed off the frontier are stored here to be written. No particular order.
	// These have entries if and only if dirtyLevel > 0.
	fullHashesTiles []*hashesTile
	fullEntryTiles  []*entryTile

	// treeSize is the current size of the tree.
	treeSize int64
}

// Clone creates a copy of Frontier that doesn't share any memory with the original.
//
// During sequencing in the MTCA we want to use a temporary copy of the frontier, so
// that if we error out the original in-memory Frontier stays untouched.
func (f *Frontier) Clone() *Frontier {
	var hashesTiles []*hashesTile
	for _, ht := range f.hashesTiles {
		hashesTiles = append(hashesTiles, ht.clone())
	}

	var fullHashesTiles []*hashesTile
	for _, ht := range f.fullHashesTiles {
		fullHashesTiles = append(fullHashesTiles, ht.clone())
	}

	entries := f.entryTile.clone()

	var fullEntryTiles []*entryTile
	for _, et := range f.fullEntryTiles {
		fullEntryTiles = append(fullEntryTiles, et.clone())
	}

	return &Frontier{
		hashesTiles:     hashesTiles,
		entryTile:       entries,
		dirtyLevel:      f.dirtyLevel,
		fullHashesTiles: fullHashesTiles,
		fullEntryTiles:  fullEntryTiles,
		treeSize:        f.treeSize,
	}
}

// hashesTile represents a tile containing hashes.
// It may be empty, partial, or full. If it's full it can only
// be part of fullHashesTiles.
type hashesTile struct {
	// Note we don't bother setting H because it's not encoded
	// in paths for tlog-tiles.
	coords tlog.Tile
	// Invariant: len(data) == coords.W
	data []tlog.Hash
}

func (h *hashesTile) clone() *hashesTile {
	return &hashesTile{
		coords: h.coords,
		data:   slices.Clone(h.data),
	}
}

func (h *hashesTile) append(val tlog.Hash) {
	h.coords.W++
	h.data = append(h.data, val)
}

// entryTile represents a tile containing entries.
// It may be empty, partial or full. If it's full it can only be
// part of fullEntryTiles.
type entryTile struct {
	coords tlog.Tile
	// data contains an entry bundle with coords.W entries.
	data []byte
}

func (e *entryTile) clone() *entryTile {
	if e == nil {
		return nil
	}
	return &entryTile{
		coords: e.coords,
		data:   bytes.Clone(e.data),
	}
}

func (e *entryTile) append(val []byte) {
	e.coords.W++
	e.data = append(e.data, val...)
}

// LoadFrontier loads the current frontier from storage, given the current tree size.
//
// Succeeds only if all the frontier tiles for that tree size exist in storage.
func LoadFrontier(ctx context.Context, s3c simpleS3, treeSize int64, prefix string) (*Frontier, error) {
	if treeSize == 0 {
		return nil, fmt.Errorf("can't load an empty tree")
	}

	entryCoords := tlog.Tile{
		L: -1, // entries layer is represented as -1.
		N: treeSize / 256,
		W: int(treeSize % 256),
	}

	entryData, err := getTile(ctx, s3c, entryCoords, prefix)
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
	if entriesCount != entryCoords.W {
		return nil, fmt.Errorf("reading entries from %q: got %d entries, want %d",
			tilePath(entryCoords), entriesCount, entryCoords.W)
	}

	entryTile := &entryTile{
		coords: entryCoords,
		data:   entryData,
	}

	var hashesTiles []*hashesTile
	// Iterate up the tree. layerSize is the number of hashes (not tiles)
	// in a layer.
	for layerSize := treeSize; layerSize > 0; layerSize /= 256 {
		coords := tlog.Tile{
			L: len(hashesTiles),
			N: layerSize / 256,
			W: int(layerSize % 256),
		}

		body, err := getTile(ctx, s3c, coords, prefix)
		if err != nil {
			return nil, err
		}

		if len(body) != coords.W*tlog.HashSize {
			return nil, fmt.Errorf("%q: got %d bytes, expected %d",
				tilePath(coords), len(body), coords.W*tlog.HashSize)
		}

		var data []tlog.Hash
		for i := 0; i < coords.W; i++ {
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

// RootHash calculates and returns the current root hash.
func (f *Frontier) RootHash() tlog.Hash {
	if len(f.hashesTiles) == 0 {
		return subtree.MTH(nil)
	}

	// Intuition:
	//  A leaf (L=0) tile's MTH is the MTH of its nodes, whether it's partial or full.
	//
	//  At level L > 0, a tile contains hashes of _complete_ subtrees from level L-1.
	//  Imagine an empty spot at the end where the next hash will go when it's complete.
	//  We temporarily put one more hash there - the MTH of the partial subtree below
	//  (if there is one). Then we calculate MTH of the level L tile including that
	//  temporary hash.
	//
	// Since MTH([x]) == x, appending a hash to an empty tile and then taking its MTH is
	// equivalent to simply skipping the tile.
	//
	// That lets us calculate the root hash like so:
	//
	//  - Climb from level 0, skipping any empty tiles.
	//  - If we don't have a hash yet, calculate MTH of the current tile.
	//  - Otherwise, calculate MTH of the current tile, with the previous tile's MTH appended.
	var currentHash tlog.Hash
	var currentHashInitialized bool
	for level := 0; level < len(f.hashesTiles); level++ {
		if f.hashesTiles[level].coords.W == 0 {
			continue
		}
		hashes := f.hashesTiles[level].data
		if !currentHashInitialized {
			currentHash = subtree.MTH(hashes)
			currentHashInitialized = true
		} else {
			currentHash = subtree.MTH(append(slices.Clone(hashes), currentHash))
		}
	}

	if !currentHashInitialized {
		// This shouldn't happen because the top tile is never empty.
		// When we add a layer we immediately put a hash in it.
		panic("shouldn't happen: all tiles on frontier are empty")
	}

	return currentHash
}

// AppendEntry appends a single MTCLogEntry to the entries tile and a
// corresponding hash to the level-0 hashes tile, updating any higher
// levels as needed.
//
// On error, the Frontier is unchanged.
func (f *Frontier) AppendEntry(mtcle *entry.MTCLogEntry) error {
	// First time appending to a zero Frontier, initialize it.
	if f.entryTile == nil {
		f.entryTile = &entryTile{
			coords: tlog.Tile{
				L: -1, // entries layer is represented as -1.
			},
		}
		f.dirtyLevel = -1
	}

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

	f.entryTile.append(bundleBytes)

	if f.entryTile.coords.W == 256 {
		// Tile is full. Queue it for writing.
		f.fullEntryTiles = append(f.fullEntryTiles, f.entryTile)
		// And set up a new, empty tile.
		f.entryTile = &entryTile{
			coords: tlog.Tile{
				L: -1, // entries layer is represented as -1.
				N: (f.treeSize + 1) / 256,
				W: 0,
			},
			data: nil,
		}
	}

	// Add the corresponding hash to level 0 (leaf hashes).
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
	currentTile.append(val)

	if currentTile.coords.W == 256 {
		// Move the full tile to the holding area and create a new empty one.
		f.fullHashesTiles = append(f.fullHashesTiles, currentTile)

		f.hashesTiles[level] = &hashesTile{
			coords: tlog.Tile{
				L: level,
				N: currentTile.coords.N + 1,
				W: 0,
			},
			data: nil,
		}

		// Append the full tile's hash to the tile above it.
		f.appendHash(subtree.MTH(currentTile.data), level+1)
	}

	f.dirtyLevel = max(f.dirtyLevel, level)
}

// Stage writes all dirty tiles to storage but does not clear their dirty status.
//
// Tiles are written to a prefix determined by the tree size and root hash, so as
// not to conflict with live-published tiles.
//
// Errors if the tree is empty.
func (f *Frontier) Stage(ctx context.Context, s3c simpleS3, prefix string) error {
	rootHash := f.RootHash()
	return f.store(ctx, s3c,
		fmt.Sprintf("pending/%s/%d-%s", prefix, f.TreeSize(),
			hex.EncodeToString(rootHash[:])))
}

// Publish writes all dirty tiles to storage and clears their dirty status.
//
// Errors if the tree is empty.
//
// TODO(#8902): This should use CopyObject, and allow overwriting.
func (f *Frontier) Publish(ctx context.Context, s3c simpleS3, prefix string) error {
	err := f.store(ctx, s3c, prefix)
	if err != nil {
		return err
	}

	f.fullHashesTiles = nil
	f.fullEntryTiles = nil
	f.dirtyLevel = -1

	return nil
}

// store stores all tiles to the given prefix.
func (f *Frontier) store(ctx context.Context, s3c simpleS3, prefix string) error {
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

	return nil
}

// writeTile writes a single tile (hash tile or entry tile).
//
// If coords.W is 0, returns nil without writing anything.
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
	if coords.W == 0 {
		// Neither write nor read an empty tile. They do not exist in storage.
		return nil
	}

	key := path.Join(prefix, tilePath(coords))

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
		Key:             &key,
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
			return fmt.Errorf("writing s3://%s/%s: %w", s3c.Bucket(), key, ErrTileExists)
		}
		return fmt.Errorf("writing s3://%s/%s: %w", s3c.Bucket(), key, err)
	}
	return nil
}

// tilePath returns a tile path like tile/0/x001/x234/067.p/23.
//
// If coords.L is -1, the path starts with tile/entries/ instead of tile/L.
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

// getTile fetches a single tile from storage, transparently decompressing if needed.
//
// If coords.W is zero, returns an empty tile without reading from storage.
func getTile(ctx context.Context, s3c simpleS3, coords tlog.Tile, prefix string) ([]byte, error) {
	if coords.W == 0 {
		// Neither write nor read an empty tile. They do not exist in storage.
		return nil, nil
	}

	key := path.Join(prefix, tilePath(coords))
	bucket := s3c.Bucket()
	resp, err := s3c.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		return nil, fmt.Errorf("fetching s3://%s/%s: %w", bucket, key, err)
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
		body = decompressed
	}

	if len(body) == 0 {
		return nil, fmt.Errorf("shouldn't happen: read empty tile body")
	}

	return body, nil
}
