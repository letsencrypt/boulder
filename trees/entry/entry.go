// Package entry defines types related to TBSCertificateLogEntry and MerkleTreeCertEntry from
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-log-entries,
// and the entry bundle encoding from https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md#log-entries
//
// The concepts fit together like so:
//
// Entry bundles contain MerkleTreeCertEntry. MerkleTreeCertEntry contains (typically) TBSCertificateLogEntry.
//
// TBSCertificateLogEntry is part of the X.509 layer. It will be used to build certificates
// (TODO: implement TBSCertificateLogEntry.ToX509).
//
// MerkleTreeCertEntry is part of the Merkle Tree layer and is what gets hashed. It provides type switching
// (needed for null_entry) and extensibility.
//
// Entry bundles are part of the tile storage layer. They provide a simple length-prefixed framing so that
// MerkleTreeCertEntries can be concatenated unambiguously.
//
// Note that neither TBSCertificateLogEntry nor MerkleTreeCertEntry carries its own length, since they will
// always be wrapped or converted into a format that has length information: entry bundles or X.509 certificate.
package entry

import (
	"bytes"
	"crypto"
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// BundleBuilder appends a sequence of MerkleTreeCertEntry to a buffer as an entry bundle.
type BundleBuilder struct {
	b cryptobyte.Builder
}

// NewBundleBuilder returns a BundleBuilder that appends to the given buffer. Like
// cryptobyte.Builder, the slice will be reallocated if its capacity is exceeded.
// Use Bytes to get the final buffer.
func NewBundleBuilder(buf []byte) *BundleBuilder {
	return &BundleBuilder{*cryptobyte.NewBuilder(buf)}
}

func (b *BundleBuilder) Bytes() ([]byte, error) {
	return b.b.Bytes()
}

// Add appends a single MerkleTreeCertEntry, with its length prefix, to the builder.
func (b *BundleBuilder) Add(merkleTreeCertificateEntry MerkleTreeCertEntry) {
	out, err := merkleTreeCertificateEntry.Marshal()
	if err != nil {
		b.b.SetError(err)
		return
	}

	b.b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(out)
	})
}

// BundleReader reads records of MerkleTreeCertEntry from the underlying buffer in the
// entry bundle format.
type BundleReader struct {
	r cryptobyte.String
}

// NewBundleReader returns a new BundleReader.
func NewBundleReader(buf []byte) *BundleReader {
	return &BundleReader{cryptobyte.String(buf)}
}

// Read reads the bytes of a single entry.
//
// Returns the parsed MerkleTreeCertEntry as well as its bytes, both of which
// reference the same memory as the original buffer.
//
// Returns MerkleTreeCertEntry{}, nil, io.EOF when there is no more to read.
func (br *BundleReader) Read() (MerkleTreeCertEntry, []byte, error) {
	if br.r.Empty() {
		return MerkleTreeCertEntry{}, nil, io.EOF
	}
	var body cryptobyte.String
	if !br.r.ReadUint16LengthPrefixed(&body) {
		return MerkleTreeCertEntry{}, nil, fmt.Errorf("malformed length")
	}

	mtce, err := unmarshalMTCE(body)
	if err != nil {
		return MerkleTreeCertEntry{}, nil, err
	}

	return mtce, body, nil
}

const typeNullEntry = 0
const typeTBSCertEntry = 1

// MerkleTreeCertEntry implements the corresponding structure from
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-log-entries
//
//	struct {
//	    MerkleTreeCertEntryExtension extensions<0..2^16-1>;
//	    MerkleTreeCertEntryType type;
//	    select (type) {
//	       case null_entry: Empty;
//	       case tbs_cert_entry: opaque tbs_cert_entry_data[N];
//	       /* May be extended with future types. */
//	    }
//	} MerkleTreeCertEntry;
//
// The zero value represents a null_entry.
type MerkleTreeCertEntry struct {
	Extensions []byte
	Type       uint16
	Value      []byte
}

// TBS returns the TBSCertificateLogEntry bytes if Type is tbs_cert_entry, or nil otherwise.
func (mtce MerkleTreeCertEntry) TBS() []byte {
	if mtce.Type == typeTBSCertEntry {
		return mtce.Value
	}
	return nil
}

// Marshal returns the encoding of its receiver.
//
// Rejects unknown MerkleTreeCertEntryTypes.
func (mtce MerkleTreeCertEntry) Marshal() ([]byte, error) {
	var builder cryptobyte.Builder
	builder.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(mtce.Extensions)
	})
	builder.AddUint16(mtce.Type)
	switch mtce.Type {
	case typeTBSCertEntry:
		// We don't encode a length prefix for Value. Per the spec:
		//      opaque tbs_cert_entry_data[N];
		//      ...
		//      When type is tbs_cert_entry, N is the number of bytes needed to
		//      consume the rest of the input.
		//
		// In other words, per TLS presentation syntax (https://datatracker.ietf.org/doc/html/rfc8446#section-3.4),
		// this is a fixed-length vector of size N, where N is known externally.
		builder.AddBytes(mtce.Value)
	case typeNullEntry:
		if len(mtce.Value) != 0 {
			return nil, fmt.Errorf("non-empty value for null_entry MerkleTreeCertEntry")
		}
		// Append nothing; the encoding of the null entry is Empty.
	default:
		return nil, fmt.Errorf("unknown MerkleTreeCertEntryType %d", mtce.Type)
	}
	return builder.Bytes()
}

// unmarshalMTCE parses a MerkleTreeCertEntry and returns it.
//
// Rejects unknown MerkleTreeCertEntryTypes.
func unmarshalMTCE(input []byte) (MerkleTreeCertEntry, error) {
	val := cryptobyte.String(input)

	var extensions cryptobyte.String
	if !val.ReadUint16LengthPrefixed(&extensions) {
		return MerkleTreeCertEntry{}, fmt.Errorf("malformed extensions")
	}

	var typ uint16
	if !val.ReadUint16(&typ) {
		return MerkleTreeCertEntry{}, fmt.Errorf("malformed type")
	}

	switch typ {
	case typeTBSCertEntry:
	case typeNullEntry:
		if len(val) > 0 {
			return MerkleTreeCertEntry{}, fmt.Errorf("null_entry with non-empty value")
		}
	default:
		return MerkleTreeCertEntry{}, fmt.Errorf("unknown MerkleTreeCertEntryType %d", typ)
	}

	// Per the spec, value is not length-prefixed. It's a fixed-length vector, where
	// the length is known externally. So it just consists of the rest of the bytes.
	return MerkleTreeCertEntry{
		Extensions: []byte(extensions),
		Type:       typ,
		Value:      []byte(val),
	}, nil
}

// FromX509 takes a DER-encoded X.509 certificate and transforms it into a TBSCertificateLogEntry,
// then returns a MerkleTreeCertEntry wrapping that TBSCertificateLogEntry.
func FromX509(in []byte, hash crypto.Hash) (MerkleTreeCertEntry, error) {
	var inner cryptobyte.String
	input := cryptobyte.String(in)

	// https://datatracker.ietf.org/doc/html/rfc5280#page-116
	//
	//		Certificate  ::=  SEQUENCE  {
	//		    tbsCertificate       TBSCertificate,
	//		    ...
	//
	//		TBSCertificate  ::=  SEQUENCE  {
	//		    version         [0]  Version DEFAULT v1,
	//		    serialNumber         CertificateSerialNumber,
	//	     ...
	if !input.ReadASN1(&inner, asn1.SEQUENCE) {
		return MerkleTreeCertEntry{}, fmt.Errorf("failed to read outer sequence")
	}
	if !input.Empty() {
		return MerkleTreeCertEntry{}, fmt.Errorf("extra bytes at end")
	}

	var tbsCertificate cryptobyte.String
	if !inner.ReadASN1(&tbsCertificate, asn1.SEQUENCE) {
		return MerkleTreeCertEntry{}, fmt.Errorf("failed to read tbsCertificate")
	}

	// https://datatracker.ietf.org/doc/html/rfc5280#page-117
	// TBSCertificate  ::=  SEQUENCE  {
	//      version         [0]  Version DEFAULT v1,
	//      serialNumber         CertificateSerialNumber,
	//      signature            AlgorithmIdentifier,
	//      issuer               Name,
	//      validity             Validity,
	//      subject              Name,
	//      subjectPublicKeyInfo SubjectPublicKeyInfo,
	//      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
	//      					 -- If present, version MUST be v2 or v3
	//      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
	//      					 -- If present, version MUST be v2 or v3
	//      extensions      [3]  Extensions OPTIONAL
	//      					 -- If present, version MUST be v3 --  }
	//
	// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-log-entries
	var version cryptobyte.String
	if !tbsCertificate.ReadASN1(&version, asn1.Tag(0).Constructed().ContextSpecific()) {
		return MerkleTreeCertEntry{}, fmt.Errorf("failed to read version")
	}
	// Version should always be v3, which is represented as an ASN.1 INTEGER 2.
	// That's tag 2, length 1, value 2.
	if !bytes.Equal(version, []byte{2, 1, 2}) {
		return MerkleTreeCertEntry{}, fmt.Errorf("invalid X.509 version")
	}
	var fields []cryptobyte.String
	for i := range 5 {
		var fieldElement cryptobyte.String
		var fieldTag asn1.Tag

		if !tbsCertificate.ReadAnyASN1Element(&fieldElement, &fieldTag) {
			return MerkleTreeCertEntry{}, fmt.Errorf("failed to read field")
		}

		switch i {
		case 2, 3, 4: // issuer, validity, subject from the TBSCertificate.
			fields = append(fields, fieldElement)
		}
	}

	// Read and transform SubjectPublicKeyInfo from the input.
	//
	// It gets written as two fields in the output:
	//    subjectPublicKeyAlgorithm AlgorithmIdentifier{PUBLIC-KEY,
	//								{PublicKeyAlgorithms}},
	//    subjectPublicKeyInfoHash  OCTET STRING,
	//
	// Use ReadASN1Element, not ReadASN1, so spki contains the tag and
	// length bytes, which should be included in the hash.
	var spki cryptobyte.String
	if !tbsCertificate.ReadASN1Element(&spki, asn1.SEQUENCE) {
		return MerkleTreeCertEntry{}, fmt.Errorf("malformed subjectPublicKeyInfo")
	}

	h := hash.New()
	h.Write(spki)
	spkiHash := h.Sum(nil)

	// Remove the tag and length from subjectPublicKeyInfo and then parse
	// subjectPublicKeyAlgorithm.
	var spkiInner cryptobyte.String
	if !spki.ReadASN1(&spkiInner, asn1.SEQUENCE) {
		return MerkleTreeCertEntry{}, fmt.Errorf("malformed subjectPublicKeyInfo")
	}
	var algID cryptobyte.String
	if !spkiInner.ReadASN1Element(&algID, asn1.SEQUENCE) {
		return MerkleTreeCertEntry{}, fmt.Errorf("malformed algorithmIdentifier")
	}

	// Read the extensions.
	//
	// Note that we've ignored issuerUniqueID and subjectUniqueID, which are OPTIONAL and
	// forbidden by the BRs. Since those fields have encoding instructions ([1] and [2]),
	// if by some chance they are present we will error when trying to read extensions,
	// which has an encoding instruction of [3].
	var extensions cryptobyte.String
	extensionsTag := asn1.Tag(3).Constructed().ContextSpecific()
	if !tbsCertificate.ReadASN1Element(&extensions, extensionsTag) {
		return MerkleTreeCertEntry{}, fmt.Errorf("error reading extensions")
	}

	if !tbsCertificate.Empty() {
		return MerkleTreeCertEntry{}, fmt.Errorf("extra bytes at end")
	}

	// TBSCertificateLogEntry ::= SEQUENCE {
	//      version               [0] EXPLICIT Version DEFAULT v1,
	//      issuer                    Name,
	//      validity                  Validity,
	//      subject                   Name,
	//      subjectPublicKeyAlgorithm AlgorithmIdentifier{PUBLIC-KEY,
	//      							{PublicKeyAlgorithms}},
	//      subjectPublicKeyInfoHash  OCTET STRING,
	//      issuerUniqueID        [1] IMPLICIT UniqueIdentifier OPTIONAL,
	//      subjectUniqueID       [2] IMPLICIT UniqueIdentifier OPTIONAL,
	//      extensions            [3] EXPLICIT Extensions{{CertExtensions}}
	//      									OPTIONAL
	// }
	//
	// TBSCertificateLogEntry, relative to TBSCertificate, lacks `serialNumber`
	// and `signature`, and encodes subjectPublicKeyInfo as its hash.
	var builder cryptobyte.Builder

	// version
	builder.AddASN1(asn1.Tag(0).Constructed().ContextSpecific(), func(child *cryptobyte.Builder) {
		child.AddASN1Int64(2)
	})

	// issuer, validity, subject
	for _, f := range fields {
		// The fields were read with ReadASN1Element so they still include
		// their tag and length. Add them straight to the builder.
		builder.AddBytes(f)
	}
	// subjectPublicKeyAlgorithm
	builder.AddBytes(algID)
	// subjectPublicKeyInfoHash
	builder.AddASN1OctetString(spkiHash)
	// extensions
	builder.AddBytes(extensions)

	tbsCertificateLogEntryBytes, err := builder.Bytes()
	if err != nil {
		return MerkleTreeCertEntry{}, err
	}

	return MerkleTreeCertEntry{
		Type:  typeTBSCertEntry,
		Value: tbsCertificateLogEntryBytes,
	}, nil
}
