// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package safebrowsing

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sort"
	"strings"

	pb "github.com/google/safebrowsing/internal/safebrowsing_proto"
)

const (
	minHashPrefixLength = 4
	maxHashPrefixLength = sha256.Size
)

// hashPrefix represents a SHA256 hash. It may either be
// be full, where len(Hash) == maxHashPrefixLength, or
// be partial, where len(Hash) >= minHashPrefixLength.
type hashPrefix string

// hashFromPattern returns a full hash for the given URL pattern.
func hashFromPattern(pattern string) hashPrefix {
	hash := sha256.New()
	hash.Write([]byte(pattern))
	return hashPrefix(hash.Sum(nil))
}

// HasPrefix reports whether other is a prefix of h.
func (h hashPrefix) HasPrefix(other hashPrefix) bool {
	return strings.HasPrefix(string(h), string(other))
}

// IsFull reports whether the hash is a full SHA256 hash.
func (h hashPrefix) IsFull() bool {
	return len(h) == maxHashPrefixLength
}

// IsValid reports whether the hash is a valid partial or full hash.
func (h hashPrefix) IsValid() bool {
	return len(h) >= minHashPrefixLength && len(h) <= maxHashPrefixLength
}

type hashPrefixes []hashPrefix

func (p hashPrefixes) Len() int           { return len(p) }
func (p hashPrefixes) Less(i, j int) bool { return p[i] < p[j] }
func (p hashPrefixes) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p hashPrefixes) Sort()              { sort.Sort(p) }

// Validate checks that the list of hash prefixes is valid. It checks the
// following parameters:
//	* That each hash prefix is valid; that is, it has a length within
//	minHashPrefixLength and maxHashPrefixLength.
//	* That the list of prefixes is sorted.
//	* That none of the hashes are prefixes of each other.
func (p hashPrefixes) Validate() error {
	var hp hashPrefix // Previous hash
	for _, h := range p {
		switch {
		case !h.IsValid():
			return errors.New("safebrowsing: invalid hash")
		case hp >= h:
			return errors.New("safebrowsing: unsorted hash list")
		case h.HasPrefix(hp) && hp != "":
			return errors.New("safebrowsing: non-unique hash prefix")
		}
		hp = h
	}
	return nil
}

func (p hashPrefixes) SHA256() []byte {
	hash := sha256.New()
	for _, b := range p {
		hash.Write([]byte(b))
	}
	return hash.Sum(nil)
}

// hashSet is a set of hash prefixes optimized for the fact that most hashes
// are only 4 bytes in length.
type hashSet struct {
	h4 map[[minHashPrefixLength]byte]uint8 // Value is maximum length prefix
	hx map[hashPrefix]struct{}
	n  int
}

func byte4(h hashPrefix) (b [4]byte) {
	b[0], b[1], b[2], b[3] = h[0], h[1], h[2], h[3]
	return b
}

func (hs *hashSet) Len() int { return hs.n }

func (hs *hashSet) Import(phs hashPrefixes) {
	hs.h4 = make(map[[minHashPrefixLength]byte]uint8, len(phs))
	hs.hx = make(map[hashPrefix]struct{})
	hs.n = len(phs)
	for _, h := range phs {
		n := hs.h4[byte4(h)]
		if len(h) > int(n) {
			hs.h4[byte4(h)] = uint8(len(h))
		}
		if len(h) > 4 {
			hs.hx[h] = struct{}{}
		}
	}
}

func (hs *hashSet) Export() hashPrefixes {
	phs := make(hashPrefixes, 0, hs.n)
	for h, n := range hs.h4 {
		if n == minHashPrefixLength {
			phs = append(phs, hashPrefix(h[:]))
		}
	}
	for h := range hs.hx {
		phs = append(phs, h)
	}
	return phs
}

func (hs *hashSet) Lookup(h hashPrefix) int {
	n := int(hs.h4[byte4(h)])
	if n <= minHashPrefixLength {
		return n
	}
	if n > len(h) {
		n = len(h)
	}
	for i := minHashPrefixLength; i <= n; i++ {
		if _, ok := hs.hx[h[:i]]; ok {
			return i
		}
	}
	return 0
}

// decodeHashes takes a ThreatEntrySet and returns a list of hashes that should
// be added to the local database.
func decodeHashes(input *pb.ThreatEntrySet) ([]hashPrefix, error) {
	switch input.CompressionType {
	case pb.CompressionType_RAW:
		raw := input.GetRawHashes()
		if raw == nil {
			return nil, errors.New("safebrowsing: nil raw hashes")
		}
		if raw.PrefixSize < minHashPrefixLength || raw.PrefixSize > maxHashPrefixLength {
			return nil, errors.New("safebrowsing: invalid hash prefix length")
		}
		if len(raw.RawHashes)%int(raw.PrefixSize) != 0 {
			return nil, errors.New("safebrowsing: invalid raw hashes")
		}
		hashes := make([]hashPrefix, len(raw.RawHashes)/int(raw.PrefixSize))
		for i := range hashes {
			hashes[i] = hashPrefix(raw.RawHashes[:raw.PrefixSize])
			raw.RawHashes = raw.RawHashes[raw.PrefixSize:]
		}
		return hashes, nil
	case pb.CompressionType_RICE:
		values, err := decodeRiceIntegers(input.GetRiceHashes())
		if err != nil {
			return nil, err
		}
		hashes := make([]hashPrefix, 0, len(values))
		var buf [4]byte
		for _, h := range values {
			binary.LittleEndian.PutUint32(buf[:], h)
			hashes = append(hashes, hashPrefix(buf[:]))
		}
		return hashes, nil
	default:
		return nil, errors.New("safebrowsing: invalid compression type")
	}
}

// decodeIndices takes a ThreatEntrySet for removals returned by the server and
// returns a list of indices that the client should remove from its database.
func decodeIndices(input *pb.ThreatEntrySet) ([]int32, error) {
	switch input.CompressionType {
	case pb.CompressionType_RAW:
		raw := input.GetRawIndices()
		if raw == nil {
			return nil, errors.New("safebrowsing: invalid raw indices")
		}
		return raw.Indices, nil
	case pb.CompressionType_RICE:
		values, err := decodeRiceIntegers(input.GetRiceIndices())
		if err != nil {
			return nil, err
		}
		indices := make([]int32, 0, len(values))
		for _, v := range values {
			indices = append(indices, int32(v))
		}
		return indices, nil
	default:
		return nil, errors.New("safebrowsing: invalid compression type")
	}
}

// decodeRiceIntegers decodes a list of Golomb-Rice encoded integers.
func decodeRiceIntegers(rice *pb.RiceDeltaEncoding) ([]uint32, error) {
	if rice == nil {
		return nil, errors.New("safebrowsing: missing rice encoded data")
	}
	if rice.RiceParameter < 0 || rice.RiceParameter > 32 {
		return nil, errors.New("safebrowsing: invalid k parameter")
	}

	values := []uint32{uint32(rice.FirstValue)}
	br := newBitReader(rice.EncodedData)
	rd := newRiceDecoder(br, uint32(rice.RiceParameter))
	for i := 0; i < int(rice.NumEntries); i++ {
		delta, err := rd.ReadValue()
		if err != nil {
			return nil, err
		}
		values = append(values, values[i]+delta)
	}

	if br.BitsRemaining() >= 8 {
		return nil, errors.New("safebrowsing: unconsumed rice encoded data")
	}
	return values, nil
}

// riceDecoder implements Golomb-Rice decoding for the Safe Browsing API.
//
// In a Rice decoder every number n is encoded as q and r where n = (q<<k) + r.
// k is a constant and a parameter of the Rice decoder and can have values in
// 0..32 inclusive. The values for q and r are encoded in the bit stream using
// different encoding schemes. The quotient comes before the remainder.
//
// The quotient q is encoded in unary coding followed by a 0. E.g., 3 would be
// encoded as 1110, 4 as 11110, and 7 as 11111110.
//
// The remainder r is encoded using k bits as an unsigned integer with the
// least-significant bits coming first in the bit stream.
//
// For more information, see the following:
//	https://en.wikipedia.org/wiki/Golomb_coding
type riceDecoder struct {
	br *bitReader
	k  uint32 // Golomb-Rice parameter
}

func newRiceDecoder(br *bitReader, k uint32) *riceDecoder {
	return &riceDecoder{br, k}
}

func (rd *riceDecoder) ReadValue() (uint32, error) {
	var q uint32
	for {
		bit, err := rd.br.ReadBits(1)
		if err != nil {
			return 0, err
		}
		q += bit
		if bit == 0 {
			break
		}
	}

	r, err := rd.br.ReadBits(int(rd.k))
	if err != nil {
		return 0, err
	}

	return q<<rd.k + r, nil
}

// The bitReader provides functionality to read bits from a slice of bytes.
//
// Logically, the bit stream is constructed such that the first byte of buf
// represent the first bits in the stream. Within a byte, the least-significant
// bits come before the most-significant bits in the bit stream.
//
// This is the same bit stream format as DEFLATE (RFC 1951).
type bitReader struct {
	buf  []byte
	mask byte
}

func newBitReader(buf []byte) *bitReader {
	return &bitReader{buf, 0x01}
}

func (br *bitReader) ReadBits(n int) (uint32, error) {
	if n < 0 || n > 32 {
		panic("invalid number of bits")
	}

	var v uint32
	for i := 0; i < n; i++ {
		if len(br.buf) == 0 {
			return v, io.ErrUnexpectedEOF
		}
		if br.buf[0]&br.mask > 0 {
			v |= 1 << uint(i)
		}
		br.mask <<= 1
		if br.mask == 0 {
			br.buf, br.mask = br.buf[1:], 0x01
		}
	}
	return v, nil
}

// BitsRemaining reports the number of bits left to read.
func (br *bitReader) BitsRemaining() int {
	n := 8 * len(br.buf)
	for m := br.mask | 1; m != 1; m >>= 1 {
		n--
	}
	return n
}
