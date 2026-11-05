// Package proof implements the MTCProof and Cosignature types from
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-certificate-format.
//
// These are used to generate the signature field of MTCs.
package proof

import (
	"bytes"
	encoding_asn1 "encoding/asn1"
	"fmt"
	"slices"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/mod/sumdb/tlog"
)

var idAlgMTCProof = encoding_asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 67}

// SigAlgEncoded returns a DER-encoded AlgorithmIdentifier suitable for
// use with MTCProof signatures. Currently it returns 1.3.6.1.5.5.7.6.67, per
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-certificate-format.
//
// AlgorithmIdentifier is encoded per https://www.rfc-editor.org/info/rfc5280/#section-4.1.1.2:
//
//	AlgorithmIdentifier  ::=  SEQUENCE  {
//	     algorithm               OBJECT IDENTIFIER,
//	     parameters              ANY DEFINED BY algorithm OPTIONAL  }
func SigAlgEncoded() []byte {
	var builder cryptobyte.Builder
	builder.AddASN1(asn1.SEQUENCE, func(sigAlg *cryptobyte.Builder) {
		sigAlg.AddASN1ObjectIdentifier(idAlgMTCProof)
	})
	return builder.BytesOrPanic()
}

// MTCProof represents the MTCProof structure from
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-certificate-format
//
//	struct {
//	    MTCLogEntryExtension extensions<0..2^16-1>;
//	    uint48 start;
//	    uint48 end;
//	    opaque inclusion_proof<0..2^16-1>;
//	    Cosignature signatures<0..2^24-1>;
//	} MTCProof;
type MTCProof struct {
	Extensions     []byte
	Start, End     int64
	InclusionProof []tlog.Hash
	Signatures     []*Cosignature
}

// Marshal serializes the bytes of an MTCProof.
func (m *MTCProof) Marshal() ([]byte, error) {
	var builder cryptobyte.Builder
	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		builder.AddBytes(m.Extensions)
	})

	if m.Start < 0 || m.Start >= 1<<48 {
		return nil, fmt.Errorf("start out of range: %d", m.Start)
	}
	if m.End < 0 || m.End >= 1<<48 {
		return nil, fmt.Errorf("end out of range: %d", m.End)
	}

	builder.AddUint48(uint64(m.Start))
	builder.AddUint48(uint64(m.End))

	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		for _, h := range m.InclusionProof {
			builder.AddBytes(h[:])
		}
	})

	// Elements [of the signatures field] MUST be ordered by cosigner_id.
	signatures := slices.Clone(m.Signatures)
	slices.SortFunc(signatures, func(a, b *Cosignature) int {
		if len(a.CosignerID) != len(b.CosignerID) {
			return len(a.CosignerID) - len(b.CosignerID)
		}
		return bytes.Compare(a.CosignerID, b.CosignerID)
	})

	var sigBytes [][]byte
	var previousCosignerID []byte
	for _, sig := range signatures {
		// Each element of the signatures field MUST have a unique cosigner_id.
		// Signatures are sorted by cosigner_id, so we can just check the previous one.
		if previousCosignerID != nil && bytes.Equal(sig.CosignerID, previousCosignerID) {
			return nil, fmt.Errorf("duplicate cosigner ID %x", sig.CosignerID)
		}
		previousCosignerID = sig.CosignerID

		sigByte, err := sig.Marshal()
		if err != nil {
			return nil, err
		}
		sigBytes = append(sigBytes, sigByte)
	}

	builder.AddUint24LengthPrefixed(func(builder *cryptobyte.Builder) {
		for _, sb := range sigBytes {
			builder.AddBytes(sb)
		}
	})

	return builder.Bytes()
}

// UnmarshalMTCProof parses the MTCProof structure from
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#certificate-format.
//
// The returned structure will have slices that point to the input data.
func UnmarshalMTCProof(in []byte) (*MTCProof, error) {
	input := cryptobyte.String(in)
	var extensions cryptobyte.String
	if !input.ReadUint16LengthPrefixed(&extensions) {
		return nil, fmt.Errorf("malformed MTCLogEntry extensions")
	}

	var start, end uint64
	if !input.ReadUint48(&start) {
		return nil, fmt.Errorf("malformed start")
	}
	if !input.ReadUint48(&end) {
		return nil, fmt.Errorf("malformed end")
	}

	var inclusionProofBytes cryptobyte.String
	if !input.ReadUint16LengthPrefixed(&inclusionProofBytes) {
		return nil, fmt.Errorf("malformed inclusion proof")
	}

	var inclusionProof []tlog.Hash
	for !inclusionProofBytes.Empty() {
		var h []byte
		if !inclusionProofBytes.ReadBytes(&h, tlog.HashSize) {
			return nil, fmt.Errorf("malformed hash")
		}
		var hh tlog.Hash
		copy(hh[:], h)
		inclusionProof = append(inclusionProof, hh)
	}

	var signaturesBytes cryptobyte.String
	if !input.ReadUint24LengthPrefixed(&signaturesBytes) {
		return nil, fmt.Errorf("malformed signature bytes")
	}

	if !input.Empty() {
		return nil, fmt.Errorf("trailing bytes")
	}

	var signatures []*Cosignature
	var previousCosignerID cryptobyte.String
	for !signaturesBytes.Empty() {
		var cosignerID cryptobyte.String
		if !signaturesBytes.ReadUint8LengthPrefixed(&cosignerID) {
			return nil, fmt.Errorf("malformed trustAnchorID")
		}

		if len(cosignerID) == 0 {
			return nil, fmt.Errorf("empty cosigner ID")
		}

		// Each element of the signatures field MUST have a unique cosigner_id.
		if bytes.Equal(previousCosignerID, cosignerID) {
			return nil, fmt.Errorf("duplicate cosigner ID")
		}

		// Elements MUST be ordered by cosigner_id (excluding length prefix) as follows:
		//  - Shorter byte strings are ordered before longer byte strings
		//  - Byte strings of the same length are ordered lexicographically
		if len(previousCosignerID) > len(cosignerID) {
			return nil, fmt.Errorf("cosigner IDs not ordered")
		}
		if len(previousCosignerID) == len(cosignerID) &&
			bytes.Compare(previousCosignerID, cosignerID) > 0 {
			return nil, fmt.Errorf("cosigner IDs not ordered")
		}
		previousCosignerID = cosignerID

		var sig cryptobyte.String
		if !signaturesBytes.ReadUint16LengthPrefixed(&sig) {
			return nil, fmt.Errorf("malformed signature")
		}

		signatures = append(signatures, &Cosignature{
			CosignerID: cosignerID,
			Signature:  sig,
		})
	}

	return &MTCProof{
		Extensions:     []byte(extensions),
		Start:          int64(start),
		End:            int64(end),
		InclusionProof: inclusionProof,
		Signatures:     signatures,
	}, nil
}

// Cosignature represents the struct of that name in
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-certificate-format.
//
// Standalone certificates carry two or more of these in addition to their inclusion proof. Landmark-relative certificates
// carry none.
//
// /* From Section 4 of draft-ietf-tls-trust-anchor-ids */
// opaque TrustAnchorID<1..2^8-1>;
//
//	struct {
//	    TrustAnchorID cosigner_id;
//	    opaque signature<0..2^16-1>;
//	} Cosignature;
type Cosignature struct {
	CosignerID []byte
	Signature  []byte
}

// Marshal serializes the bytes of a Cosignature.
func (ms *Cosignature) Marshal() ([]byte, error) {
	var builder cryptobyte.Builder
	if len(ms.CosignerID) == 0 {
		// TrustAnchorID is defined as minimum 1 byte.
		return nil, fmt.Errorf("empty cosigner ID")
	}
	builder.AddUint8LengthPrefixed(func(builder *cryptobyte.Builder) {
		builder.AddBytes(ms.CosignerID)
	})
	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		builder.AddBytes(ms.Signature)
	})
	return builder.Bytes()
}
