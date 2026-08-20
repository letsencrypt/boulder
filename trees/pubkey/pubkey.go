package pubkey

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

const typeNilPubkey = 0
const typeMTCPubkey = 1

type MTCPublicKey struct {
	typ uint16
	pub crypto.PublicKey // a SubjectPublicKeyInfo structure
}

// FromCryptoPubkey feeds a crypto.PublicKey into position in an MTCPublicKey
// struct, setting the struct "typ" to nil if the input public key is nil
func FromCryptoPubkey(in crypto.PublicKey) (*MTCPublicKey, error) {
	if in != nil {
		return &MTCPublicKey{
			typ: typeMTCPubkey,
			pub: in,
		}, nil
	} else {
		return &MTCPublicKey{
			typ: typeNilPubkey,
			pub: in,
		}, nil
	}
}

// Pubkey returns the subjectPublicKeyInfo structure bytes of an MTCPublicKey if
// type is typeMTCPubkey, or nil
func (mtcpk *MTCPublicKey) Pubkey() []byte {
	if mtcpk == nil {
		return nil
	}
	if mtcpk.typ == typeMTCPubkey {
		pkBytes, err := x509.MarshalPKIXPublicKey(mtcpk.pub)
		if err != nil {
			return nil
		}
		return pkBytes
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

	pkBytes, err := x509.MarshalPKIXPublicKey(mtcpk.pub)
	// MarshalPKIXPublicKey returns an error on nil pubkey, but we want to be able to have nil tiles
	if err != nil && err.Error() != "x509: unsupported public key type: <nil>" {
		return nil, err
	}

	switch mtcpk.typ {
	case typeMTCPubkey:
		// pkBytes is a crypto.x509 SubjectPublicKeyInfo structure
		builder.AddBytes(pkBytes)
	case typeNilPubkey:
		if len(pkBytes) != 0 {
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
// bytes fail not parse.
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
			return nil, fmt.Errorf("null_pubkey with non-empty value")
		}

		return &MTCPublicKey{
			typ: typ,
			pub: nil,
		}, nil
	default:
		return nil, fmt.Errorf("unknown MTCPubkey type %d", typ)
	}

	spki, err := x509.ParsePKIXPublicKey([]byte(val))
	if err != nil {
		return nil, err
	}

	// mtcpk just consists of the rest of the bytes, not int-prefixed
	return &MTCPublicKey{
		typ: typ,
		pub: spki,
	}, nil
}

// BundleBuilder appends a sequence of MTCPubkey to a buffer as a bundle.
type BundleBuilder struct {
	builder cryptobyte.Builder
}

// NewBundleBuilder returns a BundleBuilder that appends to the given buffer. Like
// cryptobyte.Builder, the slice will be reallocated if its capacity is exceeded.
// Use Bytes to get the final buffer.
func NewBundleBuilder(buf []byte) *BundleBuilder {
	return &BundleBuilder{*cryptobyte.NewBuilder(buf)}
}

// Bytes returns the bundle's bytes.
func (b *BundleBuilder) Bytes() ([]byte, error) {
	return b.builder.Bytes()
}

// Add appends a single MTCPubkey structure, with its length prefix, to the builder.
func (b *BundleBuilder) Add(mtcpk *MTCPublicKey) {
	out, err := mtcpk.Marshal()
	if err != nil {
		b.builder.SetError(err)
		return
	}

	b.builder.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(out)
	})
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
