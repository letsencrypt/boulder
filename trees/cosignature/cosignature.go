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
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/core/reloid"
	"github.com/letsencrypt/boulder/trees"
	"github.com/letsencrypt/boulder/trees/checkpoint"
	"github.com/letsencrypt/boulder/trees/cosigned"
)

// cosignatureAlg is the ML-DSA-44 algorithm byte in the key ID computation.
const cosignatureAlg = 0x06

// keyIDSize is the length of the key ID that begins a note signature, a prefix
// of the key hash.
const keyIDSize = 4

// timestampSize is the length of the big-endian timestamp that begins a
// TimestampedSignature.
const timestampSize = 8

// timestampedSignatureSize is the length of an ML-DSA-44 TimestampedSignature:
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

// marshalSubtreeMessage serializes the cosigned.Subtree for a cosignature over
// the subtree [start, end), with a zero timestamp.
func marshalSubtreeMessage(name, origin string, start, end int64, subtreeHash tlog.Hash) ([]byte, error) {
	message := cosigned.Subtree{
		CosignerName: name,
		LogOrigin:    origin,
		Start:        start,
		End:          end,
		SubtreeHash:  subtreeHash,
	}
	return message.Marshal()
}

// marshalCheckpointMessage serializes the cosigned.Subtree for a checkpoint
// cosignature, with start 0, as tlog-cosignature defines a checkpoint
// cosignature.
//
// https://c2sp.org/tlog-cosignature#ml-dsa-44
func marshalCheckpointMessage(name string, timestamp uint64, origin string, end int64, rootHash tlog.Hash) ([]byte, error) {
	message := cosigned.Subtree{
		CosignerName: name,
		Timestamp:    timestamp,
		LogOrigin:    origin,
		End:          end,
		SubtreeHash:  rootHash,
	}
	return message.Marshal()
}

// Cosigner produces cosignatures over checkpoints and subtrees as an MTC
// cosigner for a single log.
//
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
// cosignerID is nil, origin is not a valid log origin, or signer's public key
// is not ML-DSA-44.
func NewCosigner(cosignerID *reloid.RelativeOID, origin string, signer crypto.Signer) (*Cosigner, error) {
	if cosignerID == nil {
		return nil, errors.New("nil cosigner ID")
	}
	err := trees.CheckName(origin)
	if err != nil {
		return nil, fmt.Errorf("invalid log origin: %w", err)
	}
	pubKey, ok := signer.Public().(*mldsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cosigner public key is %T, must be ML-DSA-44", signer.Public())
	}
	if pubKey.Parameters().PublicKeySize() != mldsa.MLDSA44PublicKeySize {
		return nil, errors.New("cosigner key must be ML-DSA-44")
	}
	return &Cosigner{
		name:   oidPrefix + cosignerID.String(),
		origin: origin,
		keyID:  keyIDFor(oidPrefix+cosignerID.String(), pubKey),
		signer: signer,
	}, nil
}

// Origin returns the log origin of the log the cosigner signs for.
func (c *Cosigner) Origin() string {
	return c.origin
}

func (c *Cosigner) sign(message []byte) ([]byte, error) {
	signature, err := c.signer.Sign(nil, message, nil)
	if err != nil {
		return nil, err
	}
	if len(signature) != mldsa.MLDSA44SignatureSize {
		return nil, fmt.Errorf("signer returned %d bytes, want %d", len(signature), mldsa.MLDSA44SignatureSize)
	}
	return signature, nil
}

// CosignCheckpoint cosigns the checkpoint described by tree and returns the
// cosignature as a signed note line.
func (c *Cosigner) CosignCheckpoint(tree tlog.Tree, timestamp time.Time) ([]byte, error) {
	ts := timestamp.Unix()
	if ts < 0 {
		return nil, fmt.Errorf("invalid timestamp %d", ts)
	}
	message, err := marshalCheckpointMessage(c.name, uint64(ts), c.origin, tree.N, tree.Hash)
	if err != nil {
		return nil, err
	}
	signature, err := c.sign(message)
	if err != nil {
		return nil, err
	}

	cosignatureLine, err := c.SignatureLine(uint64(ts), signature)
	if err != nil {
		return nil, err
	}

	return cosignatureLine, nil
}

// CosignSubtree cosigns the subtree [start, end) with hash subtreeHash and
// returns the raw signature, which carries no timestamp.
func (c *Cosigner) CosignSubtree(start, end int64, subtreeHash tlog.Hash) ([]byte, error) {
	message, err := marshalSubtreeMessage(c.name, c.origin, start, end, subtreeHash)
	if err != nil {
		return nil, err
	}
	return c.sign(message)
}

// SignatureLine assembles the note signature line of the cosigner with the
// Cosigner's name and key ID plus the provided timestamp and rawSignature as
// its TimestampedSignature. Callers are responsible for ensuring the signature
// line is valid for any note text they append it to.
func (c *Cosigner) SignatureLine(timestamp uint64, rawSignature []byte) ([]byte, error) {
	if len(rawSignature) != mldsa.MLDSA44SignatureSize {
		return nil, fmt.Errorf("raw signature is %d bytes, want %d", len(rawSignature), mldsa.MLDSA44SignatureSize)
	}
	idSignature := make([]byte, keyIDSize+timestampedSignatureSize)
	binary.BigEndian.PutUint32(idSignature[:keyIDSize], c.keyID)
	binary.BigEndian.PutUint64(idSignature[keyIDSize:keyIDSize+timestampSize], timestamp)
	copy(idSignature[keyIDSize+timestampSize:], rawSignature)
	return []byte(noteSignatureLinePrefix + c.name + " " + base64.StdEncoding.EncodeToString(idSignature) + "\n"), nil
}

// Verifier is a note.Verifier that verifies an MTC cosigner's ML-DSA-44
// cosignatures over checkpoints and subtrees.
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
// nil or publicKey is not ML-DSA-44.
func NewVerifier(cosignerID *reloid.RelativeOID, publicKey *mldsa.PublicKey) (*Verifier, error) {
	if cosignerID == nil {
		return nil, errors.New("nil cosigner ID")
	}
	if publicKey.Parameters().PublicKeySize() != mldsa.MLDSA44PublicKeySize {
		return nil, errors.New("public key must be ML-DSA-44")
	}
	return &Verifier{
		keyName:   oidPrefix + cosignerID.String(),
		keyID:     keyIDFor(oidPrefix+cosignerID.String(), publicKey),
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

// Verify reports whether timestampedSignature is a valid cosignature by this
// cosigner over the checkpoint in noteText. The signed message covers the
// origin, tree size, and root hash from noteText, so extension lines do not
// affect the result. Verify satisfies note.Verifier.
//
//   - https://c2sp.org/tlog-cosignature
//   - https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-5.3.1
func (v *Verifier) Verify(noteText, timestampedSignature []byte) bool {
	parsed, err := checkpoint.Unmarshal(noteText)
	if err != nil {
		return false
	}
	if len(timestampedSignature) != timestampedSignatureSize {
		return false
	}
	timestamp := binary.BigEndian.Uint64(timestampedSignature[:timestampSize])
	if timestamp > math.MaxInt64 {
		return false
	}
	cosignedMessage, err := marshalCheckpointMessage(v.keyName, timestamp, parsed.Origin, parsed.Tree.N, parsed.Tree.Hash)
	if err != nil {
		return false
	}
	return mldsa.Verify(v.publicKey, cosignedMessage, timestampedSignature[timestampSize:], nil) == nil
}

// VerifySubtreeSignature reports whether signature is a valid subtree
// cosignature by this cosigner over the subtree [start, end) with hash
// subtreeHash of the log with origin.
//
// https://c2sp.org/tlog-cosignature#subtree-cosignatures
func (v *Verifier) VerifySubtreeSignature(origin string, start, end int64, subtreeHash tlog.Hash, signature []byte) bool {
	cosignedMessage, err := marshalSubtreeMessage(v.keyName, origin, start, end, subtreeHash)
	if err != nil {
		return false
	}
	return mldsa.Verify(v.publicKey, cosignedMessage, signature, nil) == nil
}

// CheckpointCosignature is a verified checkpoint cosignature by one cosigner,
// parsed from its signature line on the checkpoint.
//
// https://c2sp.org/tlog-cosignature#checkpoint-cosignatures
type CheckpointCosignature struct {
	// Line is the note signature line carrying the cosignature.
	Line []byte
	// Timestamp is the POSIX timestamp the cosigner signed.
	Timestamp uint64
	// Signature is the raw ML-DSA-44 signature.
	Signature []byte
}

// CheckpointCosignature returns this cosigner's checkpoint cosignature from a
// note that checkpoint.Open already verified.
func (v *Verifier) CheckpointCosignature(n *note.Note) (*CheckpointCosignature, error) {
	for _, sig := range n.Sigs {
		if sig.Name != v.keyName || sig.Hash != v.keyID {
			continue
		}
		idSignature, err := base64.StdEncoding.DecodeString(sig.Base64)
		if err != nil {
			return nil, fmt.Errorf("decoding the signature by %s: %w", v.keyName, err)
		}
		if base64.StdEncoding.EncodeToString(idSignature) != sig.Base64 {
			return nil, fmt.Errorf("signature by %s is not canonical base64", v.keyName)
		}
		if len(idSignature) != keyIDSize+timestampedSignatureSize {
			return nil, fmt.Errorf("signature by %s is %d bytes, want %d", v.keyName, len(idSignature), keyIDSize+timestampedSignatureSize)
		}
		return &CheckpointCosignature{
			Line:      []byte(noteSignatureLinePrefix + sig.Name + " " + sig.Base64 + "\n"),
			Timestamp: binary.BigEndian.Uint64(idSignature[keyIDSize : keyIDSize+timestampSize]),
			Signature: idSignature[keyIDSize+timestampSize:],
		}, nil
	}
	return nil, fmt.Errorf("note has no signature by %s", v.keyName)
}
