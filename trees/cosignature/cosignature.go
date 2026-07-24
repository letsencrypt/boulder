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
	"unicode"
	"unicode/utf8"

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
func keyIDFor(name string, pubKey *mldsa.PublicKey) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', cosignatureAlg})
	h.Write(pubKey.Bytes())
	return binary.BigEndian.Uint32(h.Sum(nil)[:keyIDSize])
}

// marshalCosignedMessage serializes the cosigned.Message for a checkpoint
// cosignature, with start 0 and end the tree size as the MTC draft section
// 5.3.1 requires for checkpoints. It rejects a non-positive end.
func marshalCosignedMessage(name string, timestamp uint64, origin string, end int64, hash tlog.Hash) ([]byte, error) {
	if end <= 0 {
		return nil, fmt.Errorf("non-positive end %d", end)
	}
	cosignedMessage := cosigned.Message{
		CosignerName: name,
		Timestamp:    timestamp,
		LogOrigin:    origin,
		Start:        0,
		End:          uint64(end),
		SubtreeHash:  hash,
	}
	return cosignedMessage.Marshal()
}

// signatureLineFor assembles the signature line "— <name> base64(keyID ||
// timestamped_signature)\n".
func signatureLineFor(name string, keyID uint32, timestampedSignature []byte) string {
	idSignature := make([]byte, keyIDSize+len(timestampedSignature))
	binary.BigEndian.PutUint32(idSignature[:keyIDSize], keyID)
	copy(idSignature[keyIDSize:], timestampedSignature)
	return noteSignatureLinePrefix + name + " " + base64.StdEncoding.EncodeToString(idSignature) + "\n"
}

// checkRelativeOID returns an error if id is not a dotted decimal OID like
// "32473.2", nil otherwise.
func checkRelativeOID(id string) error {
	if id == "" {
		return errors.New("empty")
	}
	for _, arc := range strings.Split(id, ".") {
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

// Origin returns the log origin derived from the log ID per mtc-tlog: log ID
// "32473.2.0.42" has origin "oid/1.3.6.1.4.1.32473.2.0.42". It errors if logID
// is not a dotted decimal OID.
//
// https://c2sp.org/mtc-tlog
func Origin(logID string) (string, error) {
	err := checkRelativeOID(logID)
	if err != nil {
		return "", fmt.Errorf("invalid log ID %q: %w", logID, err)
	}
	return oidPrefix + logID, nil
}

// Cosigner produces cosignatures over checkpoints as an MTC cosigner for a
// single log: the timestamp is zero, as required for cosignatures used in
// certificates, and the key is a crypto.Signer so it may be stored in an HSM.
// Both the CA cosigner and a mirror cosigning the CA's log take this role.
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

// NewCosigner returns a Cosigner for the cosigner and log with the given IDs,
// deriving its cosigner name and log origin per mtc-tlog: cosigner ID "32473.2"
// signs as "oid/1.3.6.1.4.1.32473.2". It errors if either ID is not a dotted
// decimal OID or signer's public key is not ML-DSA-44.
func NewCosigner(cosignerID, logID string, signer crypto.Signer) (*Cosigner, error) {
	err := checkRelativeOID(cosignerID)
	if err != nil {
		return nil, fmt.Errorf("invalid cosigner ID %q: %w", cosignerID, err)
	}
	origin, err := Origin(logID)
	if err != nil {
		return nil, err
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

// Origin returns the log origin derived from the log ID.
func (c *Cosigner) Origin() string {
	return c.origin
}

// CosignCheckpoint cosigns the checkpoint described by tree and returns the
// cosignature as a timestamped_signature.
func (c *Cosigner) CosignCheckpoint(tree tlog.Tree) ([]byte, error) {
	message, err := marshalCosignedMessage(c.name, 0, c.origin, tree.N, tree.Hash)
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

// CosignatureLine cosigns the checkpoint described by tree and returns the
// cosignature as a signature line, trailing newline included. For a
// timestamped_signature, use CosignCheckpoint.
func (c *Cosigner) CosignatureLine(tree tlog.Tree) (string, error) {
	signature, err := c.CosignCheckpoint(tree)
	if err != nil {
		return "", err
	}
	return signatureLineFor(c.name, c.keyID, signature), nil
}

// Verifier is a note.Verifier that verifies ML-DSA-44 cosignatures over
// checkpoints.
//
//   - https://c2sp.org/tlog-cosignature
//   - https://c2sp.org/mtc-tlog
type Verifier struct {
	name      string
	keyID     uint32
	publicKey *mldsa.PublicKey
}

var _ note.Verifier = (*Verifier)(nil)

// NewVerifier returns a Verifier for the MTC cosigner with the given ID,
// deriving its name per mtc-tlog like NewCosigner. It errors if cosignerID is
// not a dotted decimal OID or pubKey is not ML-DSA-44.
func NewVerifier(cosignerID string, pubKey *mldsa.PublicKey) (*Verifier, error) {
	err := checkRelativeOID(cosignerID)
	if err != nil {
		return nil, fmt.Errorf("invalid cosigner ID %q: %w", cosignerID, err)
	}
	if pubKey.Parameters().PublicKeySize() != mldsa.MLDSA44PublicKeySize {
		return nil, errors.New("public key must be ML-DSA-44")
	}
	return &Verifier{
		name:      oidPrefix + cosignerID,
		keyID:     keyIDFor(oidPrefix+cosignerID, pubKey),
		publicKey: pubKey,
	}, nil
}

// Name satisfies note.Verifier.
func (v *Verifier) Name() string {
	return v.name
}

// KeyHash satisfies note.Verifier.
func (v *Verifier) KeyHash() uint32 {
	return v.keyID
}

// VerifyCheckpoint returns nil if signature is a valid cosignature by this
// cosigner over the checkpoint described by origin and tree, and an error
// naming the failure otherwise. For a checkpoint note text, use Verify.
//
//   - https://c2sp.org/tlog-cosignature
//   - https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-5.3.1
func (v *Verifier) VerifyCheckpoint(origin string, tree tlog.Tree, signature []byte) error {
	if len(signature) != timestampedSignatureSize {
		return fmt.Errorf("timestamped signature is %d bytes, want %d", len(signature), timestampedSignatureSize)
	}
	timestamp := binary.BigEndian.Uint64(signature[:timestampSize])
	if timestamp > math.MaxInt64 {
		return fmt.Errorf("timestamp %d exceeds 2^63-1", timestamp)
	}
	cosignedMessage, err := marshalCosignedMessage(v.name, timestamp, origin, tree.N, tree.Hash)
	if err != nil {
		return err
	}
	err = mldsa.Verify(v.publicKey, cosignedMessage, signature[timestampSize:], nil)
	if err != nil {
		return fmt.Errorf("verifying cosignature: %s", err)
	}
	return nil
}

// Verify reports whether signature is a valid cosignature by this cosigner over
// the checkpoint in text. The signed message covers the origin, tree size, and
// root hash from text, so extension lines do not affect the result. Verify is
// the note.Verifier entry point. For an already parsed checkpoint, use
// VerifyCheckpoint.
func (v *Verifier) Verify(text, signature []byte) bool {
	parsed, err := checkpoint.Unmarshal(string(text))
	if err != nil {
		return false
	}
	return v.VerifyCheckpoint(parsed.Origin, parsed.Tree, signature) == nil
}

// TimestampedSignature extracts verifier's timestamped_signature from n. It
// returns false when verifier did not sign n or the signature is malformed. n
// must come from note.Open with verifier in its verifier list.
func TimestampedSignature(n *note.Note, verifier note.Verifier) ([]byte, bool) {
	for _, signature := range n.Sigs {
		if signature.Name != verifier.Name() || signature.Hash != verifier.KeyHash() {
			continue
		}
		idSignature, err := base64.StdEncoding.DecodeString(signature.Base64)
		if err != nil || len(idSignature) != keyIDSize+timestampedSignatureSize {
			return nil, false
		}
		return idSignature[keyIDSize:], true
	}
	return nil, false
}

// Signature returns the ML-DSA-44 signature of a timestamped_signature, the
// form certificates embed. It errors on a wrong length or a non-zero timestamp,
// which certificates cannot carry.
//
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-6.2
func Signature(timestampedSignature []byte) ([]byte, error) {
	if len(timestampedSignature) != timestampedSignatureSize {
		return nil, fmt.Errorf("timestamped signature is %d bytes, want %d", len(timestampedSignature), timestampedSignatureSize)
	}
	timestamp := binary.BigEndian.Uint64(timestampedSignature[:timestampSize])
	if timestamp != 0 {
		return nil, fmt.Errorf("timestamp is %d, want 0 for a cosignature used in certificates", timestamp)
	}
	return timestampedSignature[timestampSize:], nil
}

// Line rebuilds the signature line for a timestamped_signature, recomputing the
// key ID from name and pubKey. It does not verify the signature.
func Line(name string, pubKey *mldsa.PublicKey, timestampedSignature []byte) (string, error) {
	if name == "" {
		return "", errors.New("empty cosigner name")
	}
	if len(name) > 255 {
		return "", fmt.Errorf("cosigner name %q is %d bytes, want at most 255", name, len(name))
	}
	if !utf8.ValidString(name) {
		return "", fmt.Errorf("cosigner name %q is not valid UTF-8", name)
	}
	if strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 }) {
		return "", fmt.Errorf("cosigner name %q contains a control character", name)
	}
	if strings.IndexFunc(name, unicode.IsSpace) >= 0 {
		return "", fmt.Errorf("cosigner name %q contains a space", name)
	}
	if strings.Contains(name, "+") {
		return "", fmt.Errorf("cosigner name %q contains a plus sign", name)
	}
	if pubKey.Parameters().PublicKeySize() != mldsa.MLDSA44PublicKeySize {
		return "", errors.New("public key must be ML-DSA-44")
	}
	if len(timestampedSignature) != timestampedSignatureSize {
		return "", fmt.Errorf("timestamped signature is %d bytes, want %d", len(timestampedSignature), timestampedSignatureSize)
	}
	return signatureLineFor(name, keyIDFor(name, pubKey), timestampedSignature), nil
}
