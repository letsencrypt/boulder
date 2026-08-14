package mirror

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/tlog"
)

// maxProofLines is the most consistency proof lines a client may send in an
// add-checkpoint request per c2sp.org/tlog-witness.
const maxProofLines = 63

// maxPackageProofHashes is the most subtree consistency proof hashes an entry
// package may carry per c2sp.org/tlog-mirror.
const maxPackageProofHashes = 63

// MaxPackagesPerRequest is the most entry packages a client should send in one
// add-entries request per c2sp.org/tlog-mirror.
const MaxPackagesPerRequest = 32

// packageWidth is the entry package alignment, matching the tiled log
// interface's entry bundles.
const packageWidth = 256

// AddCheckpointRequest builds the add-checkpoint request body per
// c2sp.org/tlog-witness. The proof must be a Merkle consistency proof from
// oldSize to the checkpoint's size, empty when oldSize is zero.
func AddCheckpointRequest(oldSize int64, proof []tlog.Hash, signedCheckpoint []byte) ([]byte, error) {
	if oldSize < 0 {
		return nil, fmt.Errorf("negative old size %d", oldSize)
	}
	if oldSize == 0 && len(proof) > 0 {
		return nil, errors.New("non-empty consistency proof with old size zero")
	}
	if len(proof) > maxProofLines {
		return nil, fmt.Errorf("consistency proof has %d lines, want at most %d", len(proof), maxProofLines)
	}
	if len(signedCheckpoint) == 0 {
		return nil, errors.New("empty checkpoint")
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "old %d\n", oldSize)
	for _, h := range proof {
		b.WriteString(h.String())
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	b.Write(signedCheckpoint)
	return b.Bytes(), nil
}

// parseDecimal parses an ASCII decimal string, accepting leading zeroes since
// the specs require canonical decimals only in request bodies.
func parseDecimal(s string) (int64, error) {
	if s == "" || s[0] == '+' || s[0] == '-' {
		return 0, fmt.Errorf("malformed decimal %q", s)
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("malformed decimal %q", s)
	}
	return n, nil
}

// ParseSizeResponse parses the text/x.tlog.size body of a "409 Conflict"
// add-checkpoint response, which carries the tree size of the mirror's latest
// pending checkpoint.
func ParseSizeResponse(body []byte) (int64, error) {
	line, ok := strings.CutSuffix(string(body), "\n")
	if !ok || strings.Contains(line, "\n") {
		return 0, fmt.Errorf("malformed size response %q", body)
	}
	return parseDecimal(line)
}

// MirrorInfo is a parsed text/x.tlog.mirror-info body from a "409 Conflict" or
// "202 Accepted" add-entries response.
type MirrorInfo struct {
	// TreeSize is the tree size to use as upload_end in the next request. The
	// mirror repeats the request's upload_end if it is still a pending
	// checkpoint, otherwise it sends its current pending checkpoint's size.
	TreeSize int64
	// NextEntry is the entry to use as upload_start in the next request. It is
	// the first entry the mirror does not hold.
	NextEntry int64
	// Ticket is an opaque ticket value to send back in the next request.
	Ticket []byte
}

// ParseMirrorInfo parses a text/x.tlog.mirror-info response body.
func ParseMirrorInfo(body []byte) (MirrorInfo, error) {
	content, ok := strings.CutSuffix(string(body), "\n")
	if !ok {
		return MirrorInfo{}, fmt.Errorf("malformed mirror-info response %q", body)
	}
	lines := strings.Split(content, "\n")
	if len(lines) != 3 {
		return MirrorInfo{}, fmt.Errorf("mirror-info response has %d lines, want 3", len(lines))
	}
	treeSize, err := parseDecimal(lines[0])
	if err != nil {
		return MirrorInfo{}, fmt.Errorf("mirror-info tree size: %s", err)
	}
	nextEntry, err := parseDecimal(lines[1])
	if err != nil {
		return MirrorInfo{}, fmt.Errorf("mirror-info next entry: %s", err)
	}
	ticket, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return MirrorInfo{}, fmt.Errorf("mirror-info ticket: %s", err)
	}
	return MirrorInfo{TreeSize: treeSize, NextEntry: nextEntry, Ticket: ticket}, nil
}

// Package holds the boundaries of one entry package of an add-entries upload.
type Package struct {
	// SubtreeStart begins the subtree consistency proof's interval,
	// [SubtreeStart, End).
	SubtreeStart int64
	// EntriesStart begins the carried entries, [EntriesStart, End), exceeding
	// SubtreeStart only for the first package of an upload that does not begin
	// on a package boundary.
	EntriesStart int64
	// End is the exclusive end of both intervals.
	End int64
}

// Packages returns the first maxPackages packages of the canonical sequence for
// an upload of the entries in [uploadStart, uploadEnd). The sequence is empty
// when uploadStart equals uploadEnd.
func Packages(uploadStart, uploadEnd, maxPackages int64) ([]Package, error) {
	if uploadStart < 0 || uploadStart > uploadEnd || uploadEnd >= 1<<62 {
		return nil, fmt.Errorf("invalid upload interval [%d, %d)", uploadStart, uploadEnd)
	}
	if maxPackages < 1 {
		return nil, fmt.Errorf("non-positive maxPackages %d", maxPackages)
	}
	if uploadStart == uploadEnd {
		return nil, nil
	}
	roundedStart := uploadStart / packageWidth * packageWidth
	roundedEnd := (uploadEnd + packageWidth - 1) / packageWidth * packageWidth
	numPackages := min((roundedEnd-roundedStart)/packageWidth, maxPackages)
	packages := make([]Package, 0, numPackages)
	for i := range numPackages {
		subtreeStart := roundedStart + i*packageWidth
		packages = append(packages, Package{
			SubtreeStart: subtreeStart,
			EntriesStart: max(uploadStart, subtreeStart),
			End:          min(uploadEnd, subtreeStart+packageWidth),
		})
	}
	return packages, nil
}

// EntryPackage builds the wire form of one entry package.
func EntryPackage(entries [][]byte, proof []tlog.Hash) ([]byte, error) {
	if len(entries) == 0 {
		return nil, errors.New("entry package with no entries")
	}
	if len(proof) > maxPackageProofHashes {
		return nil, fmt.Errorf("entry package has %d proof hashes, want at most %d", len(proof), maxPackageProofHashes)
	}
	var b bytes.Buffer
	for _, entry := range entries {
		if len(entry) > 0xFFFF {
			return nil, fmt.Errorf("entry is %d bytes, want at most %d", len(entry), 0xFFFF)
		}
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(entry))) //nolint:gosec // G115: the check above rejects entries over 0xFFFF bytes.
		b.Write(length[:])
		b.Write(entry)
	}
	b.WriteByte(byte(len(proof)))
	for _, h := range proof {
		b.Write(h[:])
	}
	return b.Bytes(), nil
}

// AddEntriesRequest builds the add-entries request body. The packages must be a
// prefix of the canonical sequence for [uploadStart, uploadEnd), marshaled by
// EntryPackage.
func AddEntriesRequest(logOrigin string, uploadStart, uploadEnd int64, ticket []byte, packages [][]byte) ([]byte, error) {
	if logOrigin == "" || len(logOrigin) > 0xFFFF {
		return nil, fmt.Errorf("invalid log origin length %d", len(logOrigin))
	}
	if uploadStart < 0 || uploadStart > uploadEnd {
		return nil, fmt.Errorf("invalid upload interval [%d, %d)", uploadStart, uploadEnd)
	}
	if len(ticket) > 0xFFFF {
		return nil, fmt.Errorf("ticket is %d bytes, want at most %d", len(ticket), 0xFFFF)
	}
	var b bytes.Buffer
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(logOrigin))) //nolint:gosec // G115: the check above rejects origins over 0xFFFF bytes.
	b.Write(length[:])
	b.WriteString(logOrigin)
	var index [8]byte
	binary.BigEndian.PutUint64(index[:], uint64(uploadStart))
	b.Write(index[:])
	binary.BigEndian.PutUint64(index[:], uint64(uploadEnd)) //nolint:gosec // G115: the check above leaves uploadEnd >= uploadStart >= 0.
	b.Write(index[:])
	binary.BigEndian.PutUint16(length[:], uint16(len(ticket))) //nolint:gosec // G115: the check above rejects tickets over 0xFFFF bytes.
	b.Write(length[:])
	b.Write(ticket)
	for _, p := range packages {
		b.Write(p)
	}
	return b.Bytes(), nil
}
