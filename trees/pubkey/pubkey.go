// Package pubkey implements functions for managing the public keys that
// correspond to TBSCertificateLogEntries. It provides functions for marshaling
// them into bundles for storage in tiles, unmarshaling the tile bundles into
// sequences of the custom MTCPublicKey type, and returning the inner
// SubjectPublicKeyInfo.
//
// Pubkey bundles are sequences of uint16 length-prefixed MTCPublicKey objects.
//
// MTCPublicKey is a custom type that provides the type switching necessary to
// express null pubkey values in parallel with null_entry in the entries tiles,
// and for extensibility.
//
// SubjectPublicKeyInfo structures are part of the X.509 layer. They will be
// used to build certificates.
package pubkey

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

const typeNullPubkey = 0
const typeSPKI = 1

// MTCPublicKey is a local data type to store public keys alongside tlog-tiles
// entries for constructing MTCs. It is not defined in the MTC or tlog-tiles
// spec. This struct's "typ" is used to signal whether the "pub" is null, or is
// populated with the DER-encoded bytes of an RFC 5280 subjectPublicKeyInfo
// structure.
type MTCPublicKey struct {
	typ uint16 // typeNullPubkey or typeSPKI
	pub []byte // RFC 5280 subjectPublicKeyInfo structure
}

// FromCryptoPubkey feeds a crypto.PublicKey into position in an MTCPublicKey
// struct, returning an error if the input public key is nil
func FromCryptoPubkey(in crypto.PublicKey) (*MTCPublicKey, error) {
	if in == nil {
		return nil, errors.New("refusing to attempt x509.Marshal on nil public key input")
	}

	pkBytes, err := x509.MarshalPKIXPublicKey(in)
	if err != nil {
		return nil, err
	}

	return &MTCPublicKey{
		typ: typeSPKI,
		pub: pkBytes,
	}, nil
}

// Pubkey returns the subjectPublicKeyInfo structure bytes of an MTCPublicKey if
// its type is typeSPKI, otherwise nil.
func (mtcpk *MTCPublicKey) Pubkey() []byte {
	if mtcpk == nil {
		return nil
	}
	if mtcpk.typ == typeSPKI {
		return mtcpk.pub
	}
	return nil
}

// Marshal returns encoded pubkey bundle bytes, or an error
//
// Rejects unknown MTCPubkey types with an error. Also errors if the public key
// does not Marshal, or if pub contains bytes when typ signals all should be
// nil.
func (mtcpk *MTCPublicKey) Marshal() ([]byte, error) {
	var builder cryptobyte.Builder
	builder.AddUint16(mtcpk.typ)

	switch mtcpk.typ {
	case typeSPKI:
		// mtcpk.pub is a crypto.x509 SubjectPublicKeyInfo structure
		builder.AddBytes(mtcpk.pub)
	case typeNullPubkey:
		if len(mtcpk.pub) != 0 {
			return nil, fmt.Errorf("non-empty pubkey bytes for null MTCPubkey")
		}
		// Append nothing; the encoding of the null entry is Empty.
	default:
		return nil, fmt.Errorf("unknown MTCPubkey type %d", mtcpk.typ)
	}
	return builder.Bytes()
}

// unmarshalMTCPK parses an MTCPubkey from a bundle and returns it.
//
// Rejects unknown MTCPubkey Types with an error.
func unmarshalMTCPK(input []byte) (*MTCPublicKey, error) {
	val := cryptobyte.String(input)

	if val.Empty() {
		return nil, fmt.Errorf("cannot unmarshal empty input")
	}

	var typ uint16
	if !val.ReadUint16(&typ) {
		return nil, fmt.Errorf("malformed type")
	}

	switch typ {
	case typeSPKI:
		if val.Empty() {
			return nil, fmt.Errorf("non-null pubkey with empty value")
		}
	case typeNullPubkey:
		if !val.Empty() {
			return nil, fmt.Errorf("null pubkey with non-empty value")
		}

		return &MTCPublicKey{
			typ: typ,
			pub: nil,
		}, nil
	default:
		return nil, fmt.Errorf("unknown MTCPubkey type %d", typ)
	}

	// The rest of the bytes is the subjectPublicKeyInfo structure
	return &MTCPublicKey{
		typ: typ,
		pub: []byte(val),
	}, nil
}

// BundleReader reads records of MTCPubkey from the underlying buffer in the
// pubkey bundle format.
type BundleReader struct {
	reader cryptobyte.String
}

// NewBundleReader returns a new BundleReader.
func NewBundleReader(buf []byte) *BundleReader {
	return &BundleReader{cryptobyte.String(buf)}
}

// ReadPubkey reads the bytes of a single pubkey.
//
// Returns the parsed MTCPubkey structure as well as its public key bytes, both
// of which reference the same memory as the original buffer.
//
// Returns MTCPubkey{}, nil, io.EOF when there is no more to read.
func (br *BundleReader) ReadPubkey() (*MTCPublicKey, []byte, error) {
	if br.reader.Empty() {
		return nil, nil, io.EOF
	}
	var body cryptobyte.String
	if !br.reader.ReadUint16LengthPrefixed(&body) {
		return nil, nil, fmt.Errorf("malformed length")
	}

	mtcpk, err := unmarshalMTCPK(body)
	if err != nil {
		return nil, nil, err
	}

	return mtcpk, body, nil
}
