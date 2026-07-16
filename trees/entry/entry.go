// Package entry defines types related TBSCertificateLogEntry and MerkleTreeCertEntry from
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-log-entries,
// and the entry bundle encoding from https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md#log-entries
package entry

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// BundleWriter writes a sequence of MerkleTreeCertEntry to the underlying writer
// as entry bundles.
type BundleWriter struct {
	w io.WriteCloser
}

// NewBundleWriter returns a BundleWriter with given underlying writer.
func NewBundleWriter(w io.WriteCloser) BundleWriter {
	return BundleWriter{w}
}

func (bw BundleWriter) Close() error {
	return bw.w.Close()
}

// Write writes a single MerkleTreeLogEntry, with its length prefix, to the underlying
// writer.
func (bw BundleWriter) Write(merkleTreeCertificateEntry MerkleTreeCertEntry) error {
	out, err := merkleTreeCertificateEntry.Marshal()
	if err != nil {
		return err
	}

	return bw.writeLengthPrefixed(out)
}

// writeLengthPrefixed writes to the underlying writer a byte sequence with a two-byte length prefix.
func (bw BundleWriter) writeLengthPrefixed(in []byte) error {
	prefix := len(in)
	if prefix > math.MaxUint16 {
		return fmt.Errorf("input too long: %d bytes", len(in))
	}
	var prefixBytes [2]byte
	binary.BigEndian.PutUint16(prefixBytes[:], uint16(prefix))
	_, err := bw.w.Write(prefixBytes[:])
	if err != nil {
		return err
	}

	_, err = bw.w.Write(in)
	if err != nil {
		return err
	}

	return nil
}

// BundleReader reads records of MerkleTreeCertEntry from the underlying reader in the
// entry bundle format.
type BundleReader struct {
	r io.Reader
}

// NewBundleReader returns a new BundleReader.
func NewBundleReader(r io.Reader) BundleReader {
	return BundleReader{r}
}

// Read reads the bytes of a single entry from the underlying reader.
//
// Returns the parsed MerkleTreeCertEntry as well as its bytes.
func (br BundleReader) Read() (MerkleTreeCertEntry, []byte, error) {
	var buf [2]byte
	_, err := io.ReadFull(br.r, buf[:])
	if err != nil {
		return MerkleTreeCertEntry{}, nil, err
	}
	entryLen := binary.BigEndian.Uint16(buf[:])
	body := make([]byte, entryLen)
	_, err = io.ReadFull(br.r, body)
	if err != nil {
		return MerkleTreeCertEntry{}, nil, err
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

	builder.AddASN1(asn1.Tag(0).Constructed().ContextSpecific(), func(child *cryptobyte.Builder) {
		child.AddASN1Int64(2)
	})

	for _, f := range fields {
		// The fields were read with ReadASN1Element so they still include
		// their tag and length. Add them straight to
		builder.AddBytes(f)
	}
	builder.AddBytes(algID)
	builder.AddASN1OctetString(spkiHash)
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
