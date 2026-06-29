// Package mirror encodes and decodes the C2SP tlog-mirror request and response
// bodies.
package mirror

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/letsencrypt/boulder/trees/tile"
	"golang.org/x/mod/sumdb/tlog"
)

// maxProofHashes caps both an add-checkpoint consistency proof and an
// add-entries package's subtree consistency proof.
const maxProofHashes = 63

// AddCheckpointRequest is the add-checkpoint request body, marshaled by the
// submitter and parsed by the mirror. Set OldSize to the tree size the mirror
// is believed to hold, Proof to the RFC 6962 consistency proof from OldSize to
// the submitted checkpoint (leave it empty when OldSize is 0), and Checkpoint
// to the signed checkpoint note.
//
// https://c2sp.org/tlog-mirror
type AddCheckpointRequest struct {
	OldSize    int64
	Proof      []tlog.Hash
	Checkpoint []byte
}

// Marshal encodes the request for the wire.
func (r AddCheckpointRequest) Marshal() ([]byte, error) {
	if r.OldSize < 0 {
		return nil, fmt.Errorf("negative old size %d", r.OldSize)
	}
	if len(r.Proof) > maxProofHashes {
		return nil, fmt.Errorf("%d consistency proof hashes, at most %d allowed", len(r.Proof), maxProofHashes)
	}
	if len(r.Checkpoint) == 0 {
		return nil, errors.New("empty checkpoint")
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "old %d\n", r.OldSize)
	for _, h := range r.Proof {
		b.WriteString(h.String())
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	b.Write(r.Checkpoint)
	return b.Bytes(), nil
}

// ParseAddCheckpointRequest parses an add-checkpoint request body produced by
// Marshal. It validates structure only, not the signature or proof, so the
// mirror must still verify the checkpoint note and the consistency proof
// itself. The returned Checkpoint is a copy you may retain.
func ParseAddCheckpointRequest(body []byte) (AddCheckpointRequest, error) {
	// Split on the first blank line: header lines are never empty, while the
	// checkpoint carries its own blank line before its signatures.
	header, checkpoint, ok := bytes.Cut(body, []byte("\n\n"))
	if !ok {
		return AddCheckpointRequest{}, errors.New("add-checkpoint request has no blank line before the checkpoint")
	}
	if len(checkpoint) == 0 {
		return AddCheckpointRequest{}, errors.New("empty checkpoint")
	}
	lines := strings.Split(string(header), "\n")
	size, ok := strings.CutPrefix(lines[0], "old ")
	if !ok {
		return AddCheckpointRequest{}, errors.New("add-checkpoint request missing old size line")
	}
	oldSize, err := strconv.ParseInt(size, 10, 64)
	if err != nil || oldSize < 0 || strconv.FormatInt(oldSize, 10) != size {
		return AddCheckpointRequest{}, fmt.Errorf("malformed old size %q", size)
	}

	proofLines := lines[1:]
	if len(proofLines) > maxProofHashes {
		return AddCheckpointRequest{}, fmt.Errorf("%d consistency proof lines, at most %d allowed", len(proofLines), maxProofHashes)
	}
	proof := make([]tlog.Hash, len(proofLines))
	for i, line := range proofLines {
		proof[i], err = tlog.ParseHash(line)
		// ParseHash tolerates non-canonical base64. Require the canonical form
		// so parse-then-marshal stays exact.
		if err != nil || proof[i].String() != line {
			return AddCheckpointRequest{}, fmt.Errorf("malformed proof hash %q", line)
		}
	}

	return AddCheckpointRequest{OldSize: oldSize, Proof: proof, Checkpoint: bytes.Clone(checkpoint)}, nil
}

// Package is the index boundaries of one canonical entry package of an
// add-entries upload. It carries no entry bytes: use the boundaries to read
// entries for [EntriesStart, End) and build a subtree consistency proof over
// [SubtreeStart, End), then put both in an EntryPackage.
//
// https://c2sp.org/tlog-mirror
type Package struct {
	// SubtreeStart is the tile-aligned start of the subtree whose consistency
	// proof authenticates the package.
	SubtreeStart int64
	// EntriesStart is the first entry index carried in the package. It exceeds
	// SubtreeStart only for the first package of an upload that does not begin
	// on a tile boundary.
	EntriesStart int64
	// End is the exclusive upper bound of the package. The subtree proven is
	// [SubtreeStart, End) and the entries carried are [EntriesStart, End).
	End int64
}

// EntryPackageAt returns the i-th package of the canonical sequence for
// [uploadStart, uploadEnd) and whether i is within the sequence. The Package is
// zero when ok is false. Use it over EntryPackages for a single package or to
// walk the sequence by index without materializing it.
//
// https://c2sp.org/tlog-mirror
func EntryPackageAt(uploadStart, uploadEnd, i int64) (Package, bool) {
	if i < 0 || uploadStart < 0 || uploadStart >= uploadEnd {
		return Package{}, false
	}
	roundedStart := uploadStart / tile.Width * tile.Width
	// The last package is the one containing entry uploadEnd-1.
	if i > (uploadEnd-1-roundedStart)/tile.Width {
		return Package{}, false
	}
	base := roundedStart + i*tile.Width
	end := uploadEnd
	// Written as a subtraction: base+TileWidth could overflow int64.
	if base <= uploadEnd-tile.Width {
		end = base + tile.Width
	}
	return Package{SubtreeStart: base, EntriesStart: max(uploadStart, base), End: end}, true
}

// EntryPackages returns the whole canonical tile-aligned package sequence
// covering [uploadStart, uploadEnd), or nil when the interval is empty or
// invalid. Use EntryPackageAt instead when you want one package.
func EntryPackages(uploadStart, uploadEnd int64) []Package {
	var packages []Package
	i := int64(0)
	for {
		p, ok := EntryPackageAt(uploadStart, uploadEnd, i)
		if !ok {
			break
		}
		packages = append(packages, p)
		i++
	}
	return packages
}

// EntryPackage is the wire contents of one entry package in an add-entries
// upload. Fill Entries with the raw entry bytes for the package's
// [EntriesStart, End) range and Proof with the subtree consistency proof over
// [SubtreeStart, End). Use EntryPackages or EntryPackageAt to learn those
// boundaries.
type EntryPackage struct {
	Entries [][]byte
	Proof   []tlog.Hash
}

// AddEntriesRequest is the add-entries request body, marshaled by the submitter
// and parsed by the mirror. Set Origin to the log's checkpoint origin, the
// [UploadStart, UploadEnd) interval to the entries being uploaded, and Ticket
// to the resumption ticket from a prior mirror-info response, or empty when you
// are not resuming. Packages must be a prefix of the canonical sequence
// EntryPackages gives for that interval, each carrying exactly the entries the
// sequence assigns it.
type AddEntriesRequest struct {
	Origin      string
	UploadStart int64
	UploadEnd   int64
	Ticket      []byte
	Packages    []EntryPackage
}

// Marshal encodes the request for the wire. Packages must be a prefix of the
// canonical sequence for [UploadStart, UploadEnd), each carrying exactly the
// entry count that sequence assigns it.
func (r AddEntriesRequest) Marshal() ([]byte, error) {
	if r.Origin == "" {
		return nil, errors.New("empty origin")
	}
	if len(r.Origin) > math.MaxUint16 {
		return nil, fmt.Errorf("origin of %d bytes exceeds the uint16 limit", len(r.Origin))
	}
	if len(r.Ticket) > math.MaxUint16 {
		return nil, fmt.Errorf("ticket of %d bytes exceeds the uint16 limit", len(r.Ticket))
	}
	// The per-package checks below cannot catch a bad interval on a header-only
	// request (the spec's zero/zero probe), where a negative index would
	// wire-encode as a huge uint64.
	if r.UploadStart < 0 || r.UploadStart > r.UploadEnd {
		return nil, fmt.Errorf("invalid upload interval [%d, %d)", r.UploadStart, r.UploadEnd)
	}

	out := binary.BigEndian.AppendUint16(nil, uint16(len(r.Origin))) //nolint:gosec // G115: len(r.Origin) is bounded by the math.MaxUint16 check above.
	out = append(out, r.Origin...)
	out = binary.BigEndian.AppendUint64(out, uint64(r.UploadStart))
	out = binary.BigEndian.AppendUint64(out, uint64(r.UploadEnd))   //nolint:gosec // G115: non-negative, enforced by the interval check above.
	out = binary.BigEndian.AppendUint16(out, uint16(len(r.Ticket))) //nolint:gosec // G115: len(r.Ticket) is bounded by the math.MaxUint16 check above.
	out = append(out, r.Ticket...)

	for i, p := range r.Packages {
		canonical, ok := EntryPackageAt(r.UploadStart, r.UploadEnd, int64(i))
		if !ok {
			return nil, fmt.Errorf("%d packages, more than the canonical sequence for [%d, %d) holds", len(r.Packages), r.UploadStart, r.UploadEnd)
		}
		want := int(canonical.End - canonical.EntriesStart)
		if len(p.Entries) != want {
			return nil, fmt.Errorf("package %d carries %d entries, canonical sequence wants %d", i, len(p.Entries), want)
		}
		if len(p.Proof) > maxProofHashes {
			return nil, fmt.Errorf("package %d has %d proof hashes, at most %d allowed", i, len(p.Proof), maxProofHashes)
		}
		var err error
		for _, e := range p.Entries {
			out, err = tile.AppendEntry(out, e)
			if err != nil {
				return nil, err
			}
		}
		out = append(out, byte(len(p.Proof)))
		for _, h := range p.Proof {
			out = append(out, h[:]...)
		}
	}
	return out, nil
}

// cursor reads big-endian values off a byte slice, latching the first short
// read into err so later reads become no-ops.
type cursor struct {
	b   []byte
	err error
}

func (c *cursor) empty() bool { return len(c.b) == 0 }

func (c *cursor) bytes(n int) []byte {
	if c.err != nil {
		return nil
	}
	if n < 0 || len(c.b) < n {
		c.err = io.ErrUnexpectedEOF
		return nil
	}
	v := c.b[:n]
	c.b = c.b[n:]
	return v
}

func (c *cursor) uint8() uint8 {
	b := c.bytes(1)
	if c.err != nil {
		return 0
	}
	return b[0]
}

func (c *cursor) uint16() int {
	b := c.bytes(2)
	if c.err != nil {
		return 0
	}
	return int(binary.BigEndian.Uint16(b))
}

func (c *cursor) uint64() uint64 {
	b := c.bytes(8)
	if c.err != nil {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

func (c *cursor) hash() tlog.Hash {
	b := c.bytes(tlog.HashSize)
	if c.err != nil {
		return tlog.Hash{}
	}
	return tlog.Hash(b)
}

// ParseAddEntriesRequest parses an add-entries request body produced by
// Marshal. It validates structure only, not the proofs, so the mirror must
// still authenticate each package's Entries against its Proof. Returned entries
// and ticket are copies.
//
// truncated reports that the body ended partway through a package. When it is
// set, req holds the complete packages before the cut, not an error, and the
// mirror processes that prefix. Reject an empty-but-truncated upload
// (len(req.Packages) == 0 with truncated set). Violations that cannot come from
// interruption, such as more packages than the canonical sequence holds, are
// returned as errors.
func ParseAddEntriesRequest(body []byte) (req AddEntriesRequest, truncated bool, err error) {
	c := &cursor{b: body}
	originLen := c.uint16()
	origin := c.bytes(originLen)
	uploadStart := int64(c.uint64()) //nolint:gosec // G115: a wire value above MaxInt64 becomes negative and is rejected by the interval check below.
	uploadEnd := int64(c.uint64())   //nolint:gosec // G115: a wire value above MaxInt64 becomes negative and is rejected by the interval check below.
	ticketLen := c.uint16()
	ticket := c.bytes(ticketLen)
	if c.err != nil {
		return AddEntriesRequest{}, false, fmt.Errorf("truncated add-entries header: %s", c.err)
	}
	if len(origin) == 0 {
		return AddEntriesRequest{}, false, errors.New("empty origin")
	}
	if uploadStart < 0 || uploadEnd < 0 || uploadStart > uploadEnd {
		return AddEntriesRequest{}, false, fmt.Errorf("invalid upload interval [%d, %d)", uploadStart, uploadEnd)
	}

	req = AddEntriesRequest{
		Origin:      string(origin),
		UploadStart: uploadStart,
		UploadEnd:   uploadEnd,
		Ticket:      bytes.Clone(ticket),
	}

	for i := 0; !c.empty(); i++ {
		pkg, ok := EntryPackageAt(uploadStart, uploadEnd, int64(i))
		if !ok {
			return AddEntriesRequest{}, false, errors.New("more entry packages than the canonical sequence holds")
		}
		count := int(pkg.End - pkg.EntriesStart)
		entries := make([][]byte, count)
		for j := range entries {
			entries[j] = bytes.Clone(c.bytes(c.uint16()))
		}
		numHashes := c.uint8()
		if numHashes > maxProofHashes {
			return AddEntriesRequest{}, false, fmt.Errorf("package %d has %d proof hashes, at most %d", i, numHashes, maxProofHashes)
		}
		proof := make([]tlog.Hash, numHashes)
		for j := range proof {
			proof[j] = c.hash()
		}
		if c.err != nil {
			return req, true, nil
		}
		req.Packages = append(req.Packages, EntryPackage{Entries: entries, Proof: proof})
	}
	return req, false, nil
}

// ContentTypeSize and ContentTypeMirrorInfo are the Content-Type values for the
// size body (MarshalSize) and the mirror-info body (Info.Marshal).
const (
	ContentTypeSize       = "text/x.tlog.size"
	ContentTypeMirrorInfo = "text/x.tlog.mirror-info"
)

// MarshalSize encodes a text/x.tlog.size body carrying the mirror's current
// tree size. A mirror returns it when an add-checkpoint's old size does not
// match its own.
func MarshalSize(size int64) ([]byte, error) {
	if size < 0 {
		return nil, fmt.Errorf("negative tree size %d", size)
	}
	return fmt.Appendf(nil, "%d\n", size), nil
}

// ParseSize parses a text/x.tlog.size body into the mirror's current tree size.
// The submitter retries add-checkpoint with this as its OldSize.
func ParseSize(body []byte) (int64, error) {
	s, ok := strings.CutSuffix(string(body), "\n")
	if !ok {
		return 0, errors.New("size body does not end in newline")
	}
	size, err := strconv.ParseInt(s, 10, 64)
	if err != nil || size < 0 || strconv.FormatInt(size, 10) != s {
		return 0, fmt.Errorf("malformed size %q", s)
	}
	return size, nil
}

// Info is the text/x.tlog.mirror-info body a mirror returns to a submitter.
// TreeSize is the upload target the submitter should reach, NextEntry is the
// index to resume the next upload from, and Ticket is the resumption ticket to
// echo back in the next AddEntriesRequest.
type Info struct {
	TreeSize  int64
	NextEntry int64
	Ticket    []byte
}

// Marshal encodes the body for the wire.
func (i Info) Marshal() ([]byte, error) {
	if i.TreeSize < 0 {
		return nil, fmt.Errorf("negative tree size %d", i.TreeSize)
	}
	if i.NextEntry < 0 {
		return nil, fmt.Errorf("negative next entry %d", i.NextEntry)
	}
	return fmt.Appendf(nil, "%d\n%d\n%s\n", i.TreeSize, i.NextEntry, base64.StdEncoding.EncodeToString(i.Ticket)), nil
}

// ParseMirrorInfo parses a text/x.tlog.mirror-info body produced by
// Info.Marshal.
func ParseMirrorInfo(body []byte) (Info, error) {
	s, ok := strings.CutSuffix(string(body), "\n")
	if !ok {
		return Info{}, errors.New("mirror-info body does not end in newline")
	}
	lines := strings.Split(s, "\n")
	if len(lines) != 3 {
		return Info{}, fmt.Errorf("mirror-info has %d lines, want 3", len(lines))
	}
	treeSize, err := strconv.ParseInt(lines[0], 10, 64)
	if err != nil || treeSize < 0 || strconv.FormatInt(treeSize, 10) != lines[0] {
		return Info{}, fmt.Errorf("malformed mirror-info tree size %q", lines[0])
	}
	next, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || next < 0 || strconv.FormatInt(next, 10) != lines[1] {
		return Info{}, fmt.Errorf("malformed mirror-info next entry %q", lines[1])
	}
	ticket, err := base64.StdEncoding.DecodeString(lines[2])
	// Require canonical base64 so parse-then-marshal stays exact. Tickets are
	// mirror-produced and therefore canonical in conformant exchanges.
	if err != nil || base64.StdEncoding.EncodeToString(ticket) != lines[2] {
		return Info{}, fmt.Errorf("malformed mirror-info ticket %q", lines[2])
	}
	return Info{TreeSize: treeSize, NextEntry: next, Ticket: ticket}, nil
}
