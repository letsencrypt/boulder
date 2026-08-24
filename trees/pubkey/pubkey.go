package pubkey

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

const typeNilPubkey = 0
const typeMTCPubkey = 1

type MTCPublicKey struct {
	typ uint16
	pub []byte // a SubjectPublicKeyInfo structure
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
		typ: typeMTCPubkey,
		pub: pkBytes,
	}, nil
}

// Pubkey returns the subjectPublicKeyInfo structure bytes of an MTCPublicKey if
// type is typeMTCPubkey, or nil
func (mtcpk *MTCPublicKey) Pubkey() []byte {
	if mtcpk == nil {
		return nil
	}
	if mtcpk.typ == typeMTCPubkey {
		return mtcpk.pub
	}
	return nil
}

// Marshal returns the encoding of its receiver.
//
// Rejects unknown MTCPubkey types with an error. Also errors if the public key
// does not Marshal, or if pub contains bytes when typ signals all should be
// nil.
func (mtcpk *MTCPublicKey) Marshal() ([]byte, error) {
	var builder cryptobyte.Builder
	builder.AddUint16(mtcpk.typ)

	switch mtcpk.typ {
	case typeMTCPubkey:
		// pkBytes is a crypto.x509 SubjectPublicKeyInfo structure
		builder.AddBytes(mtcpk.pub)
	case typeNilPubkey:
		if len(mtcpk.pub) != 0 {
			return nil, fmt.Errorf("non-empty pubkey bytes for null MTCPubkey")
		}
		// Append nothing; the encoding of the null entry is Empty.
	default:
		return nil, fmt.Errorf("unknown MTCPubkey type %d", mtcpk.typ)
	}
	return builder.Bytes()
}

// unmarshalMTCPK parses a MTCPubkey and returns it.
//
// Rejects unknown MTCPubkey Types with an error. Also errors if the pubkey
// bytes fail to parse.
func unmarshalMTCPK(input []byte) (*MTCPublicKey, error) {
	val := cryptobyte.String(input)

	var typ uint16
	if !val.ReadUint16(&typ) {
		return nil, fmt.Errorf("malformed type")
	}

	switch typ {
	case typeMTCPubkey:
	case typeNilPubkey:
		if len(val) > 0 {
			return nil, fmt.Errorf("null pubkey with non-empty value")
		}

		return &MTCPublicKey{
			typ: typ,
			pub: nil,
		}, nil
	default:
		return nil, fmt.Errorf("unknown MTCPubkey type %d", typ)
	}

	// The pubkey is just the rest of the bytes. We validate it by parsing it.
	pub := []byte(val)
	_, err := x509.ParsePKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	return &MTCPublicKey{
		typ: typ,
		pub: pub,
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
