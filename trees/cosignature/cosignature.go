//go:build go1.27

package cosignature

import (
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

	"github.com/jmhodges/clock"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/trees/checkpoint"
	"github.com/letsencrypt/boulder/trees/cosigned"
)

// cosignatureAlg is the tlog-cosignature signature type byte for ML-DSA-44
// cosignatures, used in the key ID computation.
const cosignatureAlg = 0x06

// CosignatureKeyID returns the tlog-cosignature ML-DSA-44 key ID, SHA-256(name
// || "\n" || 0x06 || pubkey)[:4] as a big-endian uint32. This is the value a
// note.Verifier reports as its KeyHash. Four bytes is not collision resistant,
// so treat it as a hint, not proof of identity.
//
// https://c2sp.org/tlog-cosignature
func CosignatureKeyID(name string, pub *mldsa.PublicKey) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', cosignatureAlg})
	h.Write(pub.Bytes())
	return binary.BigEndian.Uint32(h.Sum(nil)[:4])
}

// marshalCosignedMessage builds the whole-tree checkpoint cosigned.Message over
// [0, end) and serializes it. The name and origin length limits are checked by
// cosigned.Message.Marshal.
func marshalCosignedMessage(name string, timestamp uint64, origin string, end int64, hash tlog.Hash) ([]byte, error) {
	if end < 0 {
		return nil, fmt.Errorf("end must be non-negative, got %d", end)
	}
	m := cosigned.Message{
		CosignerName: name,
		Timestamp:    timestamp,
		LogOrigin:    origin,
		Start:        0,
		End:          uint64(end),
		SubtreeHash:  hash,
	}
	return m.Marshal()
}

// MLDSACosigner produces tlog-cosignature ML-DSA-44 cosignatures over
// checkpoints. It implements note.Signer, and its Cosign method covers the
// direct path. Construct one with NewMLDSACosigner and share it. It is
// read-only after construction.
type MLDSACosigner struct {
	name  string
	key   *mldsa.PrivateKey
	keyID uint32
	clk   clock.Clock
}

// isValidCosignerName reports whether name is usable as a signed-note key name:
// non-empty, valid UTF-8, no Unicode spaces, no "+" (mirroring x/mod's
// unexported note.isValidName), and at most 255 bytes so it fits the
// cosigned_message's one-byte length prefix. Cosign builds signature lines by
// hand rather than through note.Sign, so this is our only gate.
func isValidCosignerName(name string) bool {
	return name != "" && len(name) <= 255 && utf8.ValidString(name) &&
		strings.IndexFunc(name, unicode.IsSpace) < 0 && !strings.Contains(name, "+")
}

// NewMLDSACosigner returns a cosigner that signs as name using key, stamping
// checkpoint cosignatures with the time from clk. It errors if key is not
// ML-DSA-44 or name is invalid.
func NewMLDSACosigner(name string, key *mldsa.PrivateKey, clk clock.Clock) (*MLDSACosigner, error) {
	if !isValidCosignerName(name) {
		return nil, fmt.Errorf("invalid cosigner name %q: must be 1 to 255 bytes of UTF-8 with no spaces or plus signs", name)
	}
	pub := key.PublicKey()
	if pub.Parameters().PublicKeySize() != mldsa.MLDSA44PublicKeySize {
		return nil, errors.New("cosigner key must be ML-DSA-44")
	}
	return &MLDSACosigner{
		name:  name,
		key:   key,
		keyID: CosignatureKeyID(name, pub),
		clk:   clk,
	}, nil
}

// Name satisfies note.Signer.
func (c *MLDSACosigner) Name() string {
	return c.name
}

// KeyHash satisfies note.Signer. It returns the cosigner's CosignatureKeyID.
func (c *MLDSACosigner) KeyHash() uint32 {
	return c.keyID
}

// timestampedSigSize is the length of an ML-DSA-44 timestamped_signature: an
// 8-byte big-endian timestamp followed by the 2420-byte signature.
const timestampedSigSize = 8 + mldsa.MLDSA44SignatureSize

// Sign cosigns the checkpoint in body and returns the raw timestamped_signature
// (big-endian timestamp then the ML-DSA-44 signature). Use this when you want
// the bare bytes to persist. Use Cosign for the wire signature line. body must
// be a canonically-encoded checkpoint or Sign errors. This is the note.Signer
// entry point that note.Sign calls.
//
//   - https://c2sp.org/tlog-cosignature
//   - https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-5.3.1
func (c *MLDSACosigner) Sign(body []byte) ([]byte, error) {
	parsed, err := checkpoint.Parse(string(body))
	if err != nil {
		return nil, fmt.Errorf("refusing to cosign non-checkpoint message: %w", err)
	}
	if parsed.String() != string(body) {
		return nil, errors.New("refusing to cosign non-canonical checkpoint")
	}
	// tlog-cosignature: the timestamp MUST NOT exceed 2^63-1. A pre-epoch clock
	// would wrap the uint64 conversion into that forbidden range.
	now := c.clk.Now().Unix()
	if now < 0 {
		return nil, errors.New("refusing to cosign: clock reads before the Unix epoch")
	}
	ts := uint64(now)

	msg, err := marshalCosignedMessage(c.name, ts, parsed.Origin, parsed.Tree.N, parsed.Tree.Hash)
	if err != nil {
		return nil, err
	}
	mlsig, err := c.key.SignDeterministic(msg, &mldsa.Options{})
	if err != nil {
		return nil, err
	}
	out := make([]byte, timestampedSigSize)
	binary.BigEndian.PutUint64(out[:8], ts)
	copy(out[8:], mlsig)
	return out, nil
}

// noteSigPrefix is the leading U+2014 and space that begin a signed-note
// signature line.
const noteSigPrefix = "— "

// cosignatureLineFor assembles "— <name> base64(keyID || sig)\n", the one place
// the signature line layout is written.
func cosignatureLineFor(name string, keyID uint32, timestampedSig []byte) string {
	idSig := make([]byte, 4+len(timestampedSig))
	binary.BigEndian.PutUint32(idSig[:4], keyID)
	copy(idSig[4:], timestampedSig)
	return noteSigPrefix + name + " " + base64.StdEncoding.EncodeToString(idSig) + "\n"
}

// Cosign cosigns the checkpoint in body and returns the full signed-note
// signature line, trailing newline included, ready to append to the note. Use
// Sign when you instead need the raw timestamped_signature to store.
//
//   - https://c2sp.org/tlog-cosignature
//   - https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-5.3.1
func (c *MLDSACosigner) Cosign(body []byte) (string, error) {
	sig, err := c.Sign(body)
	if err != nil {
		return "", err
	}
	return cosignatureLineFor(c.name, c.keyID, sig), nil
}

var _ note.Signer = (*MLDSACosigner)(nil)

// CosignatureLine turns a stored raw timestamped_signature back into a
// signed-note signature line, recomputing the key ID from name and pub so no
// private key is needed. Use it when you persisted cosignatures as raw blobs
// and now need the wire line. It does not verify the signature: the blob must
// come from a trusted source, such as one Cosignature returned after note.Open.
// It errors if pub is not ML-DSA-44, name is invalid, or timestampedSig is
// malformed.
//
//   - https://c2sp.org/tlog-cosignature
//   - https://c2sp.org/signed-note
func CosignatureLine(name string, pub *mldsa.PublicKey, timestampedSig []byte) (string, error) {
	if !isValidCosignerName(name) {
		return "", fmt.Errorf("invalid cosigner name %q: must be 1 to 255 bytes of UTF-8 with no spaces or plus signs", name)
	}
	if pub.Parameters().PublicKeySize() != mldsa.MLDSA44PublicKeySize {
		return "", errors.New("public key must be ML-DSA-44")
	}
	if len(timestampedSig) != timestampedSigSize {
		return "", fmt.Errorf("timestamped signature must be %d bytes, got %d", timestampedSigSize, len(timestampedSig))
	}
	// Sign cannot produce a timestamp above 2^63-1, so one here means corrupt
	// or foreign storage.
	if binary.BigEndian.Uint64(timestampedSig[:8]) > math.MaxInt64 {
		return "", errors.New("timestamped signature has a timestamp above 2^63-1")
	}
	return cosignatureLineFor(name, CosignatureKeyID(name, pub), timestampedSig), nil
}

// Cosignature extracts v's raw timestamped_signature from the opened note n,
// the bytes to persist or feed back to CosignatureLine. It returns false when v
// did not sign n or its signature is not a well-formed timestamped_signature.
// Pass a note already opened by note.Open with v among its verifiers, since
// only then does n.Sigs hold verified signatures.
//
//   - https://c2sp.org/tlog-cosignature
//   - https://c2sp.org/signed-note
func Cosignature(n *note.Note, v note.Verifier) ([]byte, bool) {
	for _, sig := range n.Sigs {
		if sig.Name != v.Name() || sig.Hash != v.KeyHash() {
			continue
		}
		idSig, err := base64.StdEncoding.DecodeString(sig.Base64)
		if err != nil || len(idSig) != 4+timestampedSigSize {
			return nil, false
		}
		return idSig[4:], true
	}
	return nil, false
}

// MLDSACosignatureVerifier verifies tlog-cosignature ML-DSA-44 cosignatures. It
// implements note.Verifier, so the usual path is to pass it to note.Open and
// then ask Cosignature about the result.
type MLDSACosignatureVerifier struct {
	name  string
	keyID uint32
	pub   *mldsa.PublicKey
}

// NewMLDSACosignatureVerifier returns a verifier for cosignatures made as name
// under pub. It errors if pub is not ML-DSA-44 or name is invalid.
func NewMLDSACosignatureVerifier(name string, pub *mldsa.PublicKey) (*MLDSACosignatureVerifier, error) {
	if !isValidCosignerName(name) {
		return nil, fmt.Errorf("invalid cosigner name %q: must be 1 to 255 bytes of UTF-8 with no spaces or plus signs", name)
	}
	if pub.Parameters().PublicKeySize() != mldsa.MLDSA44PublicKeySize {
		return nil, errors.New("public key must be ML-DSA-44")
	}
	return &MLDSACosignatureVerifier{name: name, keyID: CosignatureKeyID(name, pub), pub: pub}, nil
}

// Name satisfies note.Verifier.
func (v *MLDSACosignatureVerifier) Name() string {
	return v.name
}

// KeyHash satisfies note.Verifier. It returns the cosigner's CosignatureKeyID.
func (v *MLDSACosignatureVerifier) KeyHash() uint32 {
	return v.keyID
}

// Verify reports whether sig is a valid whole-tree cosignature by this cosigner
// over the checkpoint in body. It is the note.Verifier entry point that
// note.Open calls.
//
//   - https://c2sp.org/tlog-cosignature
//   - https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-5.3.1
func (v *MLDSACosignatureVerifier) Verify(body, sig []byte) bool {
	if len(sig) != timestampedSigSize {
		return false
	}
	// tlog-cosignature caps the timestamp at 2^63-1.
	timestamp := binary.BigEndian.Uint64(sig[:8])
	if timestamp > math.MaxInt64 {
		return false
	}
	mlsig := sig[8:]

	parsed, err := checkpoint.Parse(string(body))
	if err != nil {
		return false
	}
	msg, err := marshalCosignedMessage(v.name, timestamp, parsed.Origin, parsed.Tree.N, parsed.Tree.Hash)
	if err != nil {
		return false
	}
	return mldsa.Verify(v.pub, msg, mlsig, &mldsa.Options{}) == nil
}

var _ note.Verifier = (*MLDSACosignatureVerifier)(nil)
