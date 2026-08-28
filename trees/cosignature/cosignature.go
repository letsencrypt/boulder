//go:build go1.27

package cosignature

import (
	"crypto"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/trees/checkpoint"
	"github.com/letsencrypt/boulder/trees/cosigned"
)

// cosignatureAlg is the ML-DSA-44 algorithm byte in the key ID computation.
const cosignatureAlg = 0x06

// keyIDSize is the length of the key ID that begins a note signature, a prefix
// of the key hash.
const keyIDSize = 4

// timestampSize is the length of the big-endian timestamp that begins a
// timestamped_signature.
const timestampSize = 8

// timestampedSignatureSize is the length of an ML-DSA-44 timestamped_signature:
// the timestamp followed by the signature.
const timestampedSignatureSize = timestampSize + mldsa.MLDSA44SignatureSize

// noteSignatureLinePrefix is the U+2014 and space that begin a signature line.
const noteSignatureLinePrefix = "— "

// oidPrefix begins every mtc-tlog cosigner name and log origin: the IANA
// private enterprise arc an MTC ID is relative to.
const oidPrefix = "oid/1.3.6.1.4.1."

// keyIDFor returns the key ID of an ML-DSA-44 cosigner: SHA-256(name || "\n" ||
// 0x06 || pubkey)[:4] as a big-endian uint32.
//
// https://c2sp.org/tlog-cosignature
func keyIDFor(name string, publicKey *mldsa.PublicKey) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', cosignatureAlg})
	h.Write(publicKey.Bytes())
	return binary.BigEndian.Uint32(h.Sum(nil)[:keyIDSize])
}

// marshalCheckpointMessage serializes the cosigned.Message for a checkpoint
// cosignature, with start 0 and end the tree size as the MTC draft section
// 5.3.1 requires for checkpoints. It rejects a non-positive end.
func marshalCheckpointMessage(name string, timestamp uint64, origin string, end int64, rootHash tlog.Hash) ([]byte, error) {
	if end <= 0 {
		return nil, fmt.Errorf("non-positive end %d", end)
	}
	cosignedMessage := cosigned.Message{
		CosignerName: name,
		Timestamp:    timestamp,
		LogOrigin:    origin,
		Start:        0,
		End:          uint64(end),
		SubtreeHash:  rootHash,
	}
	return cosignedMessage.Marshal()
}

// checkRelativeOID returns an error if id is not a dotted decimal OID like
// "32473.2", nil otherwise.
func checkRelativeOID(id string) error {
	if id == "" {
		return errors.New("empty relative OID")
	}
	for arc := range strings.SplitSeq(id, ".") {
		if arc == "" {
			return errors.New("empty arc")
		}
		if len(arc) > 1 && arc[0] == '0' {
			return fmt.Errorf("arc %q has a leading zero", arc)
		}
		for _, r := range arc {
			if r < '0' || r > '9' {
				return fmt.Errorf("arc %q is not decimal", arc)
			}
		}
	}
	return nil
}

// Cosigner produces cosignatures over checkpoints as an MTC cosigner for a
// single log: the timestamp is zero, as required for cosignatures used in
// certificates, and the key is a crypto.Signer so it may be stored in an HSM.
// Both the CA cosigner and the mirror cosigner use this.
//
//   - https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-5.3.1
//   - https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-6.2
//   - https://c2sp.org/mtc-tlog
type Cosigner struct {
	name   string
	origin string
	keyID  uint32
	signer crypto.Signer
}

// NewCosigner returns a Cosigner for the cosigner with the given ID over the
// log with the given log origin, deriving its cosigner name per mtc-tlog:
// cosigner ID "32473.2" signs as "oid/1.3.6.1.4.1.32473.2". It errors if
// cosignerID is not a dotted decimal OID, origin is empty, or signer's public
// key is not ML-DSA-44.
func NewCosigner(cosignerID, origin string, signer crypto.Signer) (*Cosigner, error) {
	err := checkRelativeOID(cosignerID)
	if err != nil {
		return nil, fmt.Errorf("invalid cosigner ID %q: %w", cosignerID, err)
	}
	if origin == "" {
		return nil, errors.New("empty log origin")
	}
	pubKey, ok := signer.Public().(*mldsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cosigner public key is %T, must be ML-DSA-44", signer.Public())
	}
	if pubKey.Parameters().PublicKeySize() != mldsa.MLDSA44PublicKeySize {
		return nil, errors.New("cosigner key must be ML-DSA-44")
	}
	return &Cosigner{
		name:   oidPrefix + cosignerID,
		origin: origin,
		keyID:  keyIDFor(oidPrefix+cosignerID, pubKey),
		signer: signer,
	}, nil
}

// Origin returns the log origin of the log the cosigner signs for.
func (c *Cosigner) Origin() string {
	return c.origin
}

// CosignCheckpoint cosigns the checkpoint described by tree and returns the
// cosignature as a timestamped_signature.
func (c *Cosigner) CosignCheckpoint(tree tlog.Tree) ([]byte, error) {
	message, err := marshalCheckpointMessage(c.name, 0, c.origin, tree.N, tree.Hash)
	if err != nil {
		return nil, err
	}
	signature, err := c.signer.Sign(nil, message, nil)
	if err != nil {
		return nil, err
	}
	if len(signature) != mldsa.MLDSA44SignatureSize {
		return nil, fmt.Errorf("signer returned %d bytes, want %d", len(signature), mldsa.MLDSA44SignatureSize)
	}
	out := make([]byte, timestampedSignatureSize)
	copy(out[timestampSize:], signature)
	return out, nil
}

// Verifier is a note.Verifier that verifies an MTC cosigner's ML-DSA-44
// cosignatures over checkpoints.
//
//   - https://c2sp.org/tlog-cosignature
//   - https://c2sp.org/mtc-tlog
type Verifier struct {
	keyName   string
	keyID     uint32
	publicKey *mldsa.PublicKey
}

var _ note.Verifier = (*Verifier)(nil)

// NewVerifier returns a Verifier for the MTC cosigner with the given ID,
// deriving its name per mtc-tlog like NewCosigner. It errors if cosignerID is
// not a dotted decimal OID or publicKey is not ML-DSA-44.
func NewVerifier(cosignerID string, publicKey *mldsa.PublicKey) (*Verifier, error) {
	err := checkRelativeOID(cosignerID)
	if err != nil {
		return nil, fmt.Errorf("invalid cosigner ID %q: %w", cosignerID, err)
	}
	if publicKey.Parameters().PublicKeySize() != mldsa.MLDSA44PublicKeySize {
		return nil, errors.New("public key must be ML-DSA-44")
	}
	return &Verifier{
		keyName:   oidPrefix + cosignerID,
		keyID:     keyIDFor(oidPrefix+cosignerID, publicKey),
		publicKey: publicKey,
	}, nil
}

// Name satisfies note.Verifier.
func (v *Verifier) Name() string {
	return v.keyName
}

// KeyHash satisfies note.Verifier.
func (v *Verifier) KeyHash() uint32 {
	return v.keyID
}

// VerifyCheckpoint returns nil if timestampedSignature is a valid cosignature
// by this cosigner over the checkpoint described by origin and tree, and an
// error naming the failure otherwise. For a checkpoint note text, use Verify.
//
//   - https://c2sp.org/tlog-cosignature
//   - https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-5.3.1
func (v *Verifier) VerifyCheckpoint(origin string, tree tlog.Tree, timestampedSignature []byte) error {
	if len(timestampedSignature) != timestampedSignatureSize {
		return fmt.Errorf("timestamped signature is %d bytes, want %d", len(timestampedSignature), timestampedSignatureSize)
	}
	timestamp := binary.BigEndian.Uint64(timestampedSignature[:timestampSize])
	if timestamp > math.MaxInt64 {
		return fmt.Errorf("timestamp %d exceeds 2^63-1", timestamp)
	}
	cosignedMessage, err := marshalCheckpointMessage(v.keyName, timestamp, origin, tree.N, tree.Hash)
	if err != nil {
		return err
	}
	err = mldsa.Verify(v.publicKey, cosignedMessage, timestampedSignature[timestampSize:], nil)
	if err != nil {
		return fmt.Errorf("verifying cosignature: %s", err)
	}
	return nil
}

// Verify reports whether signature is a valid cosignature by this cosigner over
// the checkpoint in noteText. The signed message covers the origin, tree size,
// and root hash from noteText, so extension lines do not affect the result.
// Verify is the note.Verifier entry point. For an already parsed checkpoint,
// use VerifyCheckpoint.
func (v *Verifier) Verify(noteText, timestampedSignature []byte) bool {
	parsed, err := checkpoint.Unmarshal(noteText)
	if err != nil {
		return false
	}
	return v.VerifyCheckpoint(parsed.Origin, parsed.Tree, timestampedSignature) == nil
}

// FilterByVerify returns the timestamped_signature by this verifier's cosigner
// from the signatureLines over noteText, ignoring lines by other keys. It
// errors if the two do not form a well-formed note, if no line is by that
// cosigner, or if its signature does not verify.
func (v *Verifier) FilterByVerify(noteText, signatureLines []byte) ([]byte, error) {
	n, err := note.Open(fmt.Appendf(nil, "%s\n%s", noteText, signatureLines), note.VerifierList(v))
	if err != nil {
		return nil, fmt.Errorf("opening the cosigned note: %s", err)
	}
	idSignature, err := base64.StdEncoding.DecodeString(n.Sigs[0].Base64)
	if err != nil {
		return nil, fmt.Errorf("decoding the signature by %s: %s", v.keyName, err)
	}
	return idSignature[keyIDSize:], nil
}

// RawSignature returns the ML-DSA-44 signature from a timestamped_signature,
// the form certificates embed. It errors if the input has the wrong length or a
// non-zero timestamp, which certificates cannot carry.
//
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-6.2
func RawSignature(timestampedSignature []byte) ([]byte, error) {
	if len(timestampedSignature) != timestampedSignatureSize {
		return nil, fmt.Errorf("timestamped signature is %d bytes, want %d", len(timestampedSignature), timestampedSignatureSize)
	}
	timestamp := binary.BigEndian.Uint64(timestampedSignature[:timestampSize])
	if timestamp != 0 {
		return nil, fmt.Errorf("timestamp is %d, want 0 for a cosignature used in certificates", timestamp)
	}
	return timestampedSignature[timestampSize:], nil
}

// SignatureLine reassembles the note signature line of the cosigner with the
// given keyName, keyID, and rawSignature. Callers are responsible for ensuring
// the signature line is valid for any note text they append it to.
func SignatureLine(keyName string, keyID uint32, rawSignature []byte) ([]byte, error) {
	if len(rawSignature) != mldsa.MLDSA44SignatureSize {
		return nil, fmt.Errorf("raw signature is %d bytes, want %d", len(rawSignature), mldsa.MLDSA44SignatureSize)
	}
	idSignature := make([]byte, keyIDSize+timestampedSignatureSize)
	binary.BigEndian.PutUint32(idSignature[:keyIDSize], keyID)
	copy(idSignature[keyIDSize+timestampSize:], rawSignature)
	return []byte(noteSignatureLinePrefix + keyName + " " + base64.StdEncoding.EncodeToString(idSignature) + "\n"), nil
}
