package tlog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jmhodges/clock"
	"golang.org/x/mod/sumdb/note"
)

// cosignatureAlg is the tlog-cosignature signature type byte for Ed25519
// cosignatures, used in the key ID computation.
const cosignatureAlg = 0x04

// noteSigPrefix is the leading U+2014 and space that begin a signed-note
// signature line.
const noteSigPrefix = "— "

// isValidCosignerName reports whether name is usable as a signed-note key
// name: non-empty, valid UTF-8, no Unicode spaces, no "+" (mirroring x/mod's
// unexported note.isValidName). Cosign builds signature lines by hand rather
// than through note.Sign, so this is our only gate.
func isValidCosignerName(name string) bool {
	return name != "" && utf8.ValidString(name) && strings.IndexFunc(name, unicode.IsSpace) < 0 && !strings.Contains(name, "+")
}

// CosignatureKeyID returns the tlog-cosignature Ed25519 key ID:
// SHA-256(name || "\n" || 0x04 || pubkey)[:4], as a big-endian uint32.
func CosignatureKeyID(name string, pub ed25519.PublicKey) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', cosignatureAlg})
	h.Write(pub)
	return binary.BigEndian.Uint32(h.Sum(nil)[:4])
}

// cosignatureMessage builds the tlog-cosignature Ed25519 signed message: the
// "cosignature/v1" header line, the timestamp line, and the cosigned checkpoint
// body (which must include its trailing newline and no signature lines).
func cosignatureMessage(timestamp uint64, body []byte) []byte {
	var b bytes.Buffer
	b.WriteString("cosignature/v1\n")
	b.WriteString("time ")
	b.WriteString(strconv.FormatUint(timestamp, 10))
	b.WriteByte('\n')
	b.Write(body)
	return b.Bytes()
}

// Ed25519Cosigner produces tlog-cosignature Ed25519 cosignatures over
// checkpoints, as a note.Signer. Checkpoint cosignatures only: cosigners
// whose signatures appear in MTC standalone certificates MUST be ML-DSA-44
// MTC cosigners (mtc-tlog, Cosigners), a different format that will land
// alongside this type.
type Ed25519Cosigner struct {
	name  string
	key   ed25519.PrivateKey
	keyID uint32
	clk   clock.Clock
}

// NewEd25519Cosigner returns a cosigner that signs as name with key, drawing
// cosignature timestamps from clk.
func NewEd25519Cosigner(name string, key ed25519.PrivateKey, clk clock.Clock) (*Ed25519Cosigner, error) {
	if !isValidCosignerName(name) {
		return nil, fmt.Errorf("invalid cosigner name %q: must be non-empty UTF-8 with no spaces or plus signs", name)
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(key))
	}
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("ed25519 private key has unexpected public key type")
	}
	return &Ed25519Cosigner{
		name:  name,
		key:   key,
		keyID: CosignatureKeyID(name, pub),
		clk:   clk,
	}, nil
}

// Name returns the key name that identifies this cosigner in note signature
// lines.
func (c *Ed25519Cosigner) Name() string {
	return c.name
}

// KeyHash returns the cosigner's note key hash, the four-byte key ID from
// CosignatureKeyID.
func (c *Ed25519Cosigner) KeyHash() uint32 {
	return c.keyID
}

// Sign returns the timestamped_signature for the cosigned checkpoint body: the
// big-endian timestamp followed by the Ed25519 signature. It refuses to sign
// anything but a canonically-encoded checkpoint, so a malformed or
// non-canonical note can never be cosigned.
func (c *Ed25519Cosigner) Sign(body []byte) ([]byte, error) {
	parsed, err := ParseCheckpoint(string(body))
	if err != nil {
		return nil, fmt.Errorf("refusing to cosign non-checkpoint message: %w", err)
	}
	if parsed.String() != string(body) {
		return nil, errors.New("refusing to cosign non-canonical checkpoint")
	}
	// tlog-cosignature: the timestamp MUST NOT exceed 2^63-1. A pre-epoch
	// clock would wrap the uint64 conversion into that forbidden range.
	now := c.clk.Now().Unix()
	if now < 0 {
		return nil, errors.New("refusing to cosign: clock reads before the Unix epoch")
	}
	timestamp := uint64(now)
	sig := ed25519.Sign(c.key, cosignatureMessage(timestamp, body))
	out := make([]byte, 8+ed25519.SignatureSize)
	binary.BigEndian.PutUint64(out[:8], timestamp)
	copy(out[8:], sig)
	return out, nil
}

// Cosign returns the complete signed-note signature line cosigning the given
// checkpoint body, including its trailing newline.
func (c *Ed25519Cosigner) Cosign(body []byte) (string, error) {
	sig, err := c.Sign(body)
	if err != nil {
		return "", err
	}
	return cosignatureLineFor(c.name, c.keyID, sig), nil
}

var _ note.Signer = (*Ed25519Cosigner)(nil)

// cosignatureLineFor assembles "— <name> base64(keyID || sig)\n", the one
// place the signature line layout is written.
func cosignatureLineFor(name string, keyID uint32, timestampedSig []byte) string {
	idSig := make([]byte, 4+len(timestampedSig))
	binary.BigEndian.PutUint32(idSig[:4], keyID)
	copy(idSig[4:], timestampedSig)
	return noteSigPrefix + name + " " + base64.StdEncoding.EncodeToString(idSig) + "\n"
}

// CosignatureLine renders a stored timestamped_signature as its signed-note
// signature line, recomputing the key ID from the name and public key so no
// signing key is needed. It is the inverse of Cosignature, for consumers
// that persist cosignatures as raw blobs.
func CosignatureLine(name string, pub ed25519.PublicKey, timestampedSig []byte) (string, error) {
	if !isValidCosignerName(name) {
		return "", fmt.Errorf("invalid cosigner name %q: must be non-empty UTF-8 with no spaces or plus signs", name)
	}
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	if len(timestampedSig) != 8+ed25519.SignatureSize {
		return "", fmt.Errorf("timestamped signature must be %d bytes, got %d", 8+ed25519.SignatureSize, len(timestampedSig))
	}
	// Sign cannot produce a timestamp above 2^63-1, so one here means
	// corrupt or foreign storage.
	if binary.BigEndian.Uint64(timestampedSig[:8]) > math.MaxInt64 {
		return "", errors.New("timestamped signature has a timestamp above 2^63-1")
	}
	return cosignatureLineFor(name, CosignatureKeyID(name, pub), timestampedSig), nil
}

// Cosignature returns the raw timestamped_signature of v's verified
// signature on n, reporting false when v did not sign n or the signature is
// not a timestamped_signature. As with CosignedBy, v must be one of the
// verifiers that opened n.
func Cosignature(n *note.Note, v note.Verifier) ([]byte, bool) {
	for _, sig := range n.Sigs {
		if sig.Name != v.Name() || sig.Hash != v.KeyHash() {
			continue
		}
		idSig, err := base64.StdEncoding.DecodeString(sig.Base64)
		if err != nil || len(idSig) != 4+8+ed25519.SignatureSize {
			return nil, false
		}
		return idSig[4:], true
	}
	return nil, false
}

// VerifyCosignature verifies a tlog-cosignature Ed25519 timestamped_signature
// over the given checkpoint body, returning the embedded timestamp.
func VerifyCosignature(pub ed25519.PublicKey, body, sig []byte) (timestamp uint64, ok bool) {
	if len(sig) != 8+ed25519.SignatureSize {
		return 0, false
	}
	timestamp = binary.BigEndian.Uint64(sig[:8])
	// tlog-cosignature: the timestamp MUST NOT exceed 2^63-1.
	if timestamp > math.MaxInt64 {
		return 0, false
	}
	return timestamp, ed25519.Verify(pub, cosignatureMessage(timestamp, body), sig[8:])
}

// CosignatureVerifier verifies tlog-cosignature Ed25519 cosignatures, as a
// note.Verifier.
type CosignatureVerifier struct {
	name  string
	keyID uint32
	pub   ed25519.PublicKey
}

// NewCosignatureVerifier returns a verifier for cosignatures from name with the
// given public key.
func NewCosignatureVerifier(name string, pub ed25519.PublicKey) (*CosignatureVerifier, error) {
	if !isValidCosignerName(name) {
		return nil, fmt.Errorf("invalid cosigner name %q: must be non-empty UTF-8 with no spaces or plus signs", name)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	return &CosignatureVerifier{name: name, keyID: CosignatureKeyID(name, pub), pub: pub}, nil
}

// Name returns the key name that identifies this cosigner in note signature
// lines.
func (v *CosignatureVerifier) Name() string {
	return v.name
}

// KeyHash returns the cosigner's note key hash, the four-byte key ID from
// CosignatureKeyID.
func (v *CosignatureVerifier) KeyHash() uint32 {
	return v.keyID
}

// Verify reports whether sig is a valid cosignature by this cosigner over the
// checkpoint body msg.
func (v *CosignatureVerifier) Verify(msg, sig []byte) bool {
	_, ok := VerifyCosignature(v.pub, msg, sig)
	return ok
}

var _ note.Verifier = (*CosignatureVerifier)(nil)

// CosignedBy reports whether the opened note carries a verified signature
// from the cosigner identified by v. The (name, key ID) match is only
// meaningful when v was among the verifiers that opened n: n.Sigs holds only
// verified signatures, and the 4-byte key ID is not collision resistant.
func CosignedBy(n *note.Note, v note.Verifier) bool {
	for _, sig := range n.Sigs {
		if sig.Name == v.Name() && sig.Hash == v.KeyHash() {
			return true
		}
	}
	return false
}
