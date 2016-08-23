package nonce

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/letsencrypt/boulder/metrics"
)

// MaxUsed defines the maximum number of Nonces we're willing to hold in
// memory.
const MaxUsed = 65536
const nonceLen = 32

var errInvalidNonceLength = errors.New("invalid nonce length")

// NonceService generates, cancels, and tracks Nonces.
type NonceService struct {
	mu       sync.Mutex
	latest   int64
	earliest int64
	used     map[int64]bool
	gcm      cipher.AEAD
	maxUsed  int
	stats    metrics.Scope
}

// NewNonceService constructs a NonceService with defaults
func NewNonceService(parent metrics.Scope) (*NonceService, error) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		panic("Failure in NewCipher: " + err.Error())
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		panic("Failure in NewGCM: " + err.Error())
	}

	return &NonceService{
		earliest: 0,
		latest:   0,
		used:     make(map[int64]bool, MaxUsed),
		gcm:      gcm,
		maxUsed:  MaxUsed,
		stats:    parent.NewScope("NonceService"),
	}, nil
}

func (ns *NonceService) encrypt(counter int64) (string, error) {
	// Generate a nonce with upper 4 bytes zero
	nonce := make([]byte, 12)
	for i := 0; i < 4; i++ {
		nonce[i] = 0
	}
	if _, err := rand.Read(nonce[4:]); err != nil {
		return "", err
	}

	// Encode counter to plaintext
	pt := make([]byte, 8)
	ctr := big.NewInt(counter)
	pad := 8 - len(ctr.Bytes())
	copy(pt[pad:], ctr.Bytes())

	// Encrypt
	ret := make([]byte, nonceLen)
	ct := ns.gcm.Seal(nil, nonce, pt, nil)
	copy(ret, nonce[4:])
	copy(ret[8:], ct)
	return base64.RawURLEncoding.EncodeToString(ret), nil
}

func (ns *NonceService) decrypt(nonce string) (int64, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		return 0, err
	}
	if len(decoded) != nonceLen {
		return 0, errInvalidNonceLength
	}

	n := make([]byte, 12)
	for i := 0; i < 4; i++ {
		n[i] = 0
	}
	copy(n[4:], decoded[:8])

	pt, err := ns.gcm.Open(nil, n, decoded[8:], nil)
	if err != nil {
		return 0, err
	}

	ctr := big.NewInt(0)
	ctr.SetBytes(pt)
	return ctr.Int64(), nil
}

// Nonce provides a new Nonce.
func (ns *NonceService) Nonce() (string, error) {
	ns.mu.Lock()
	ns.latest++
	latest := ns.latest
	ns.mu.Unlock()
	defer ns.stats.Inc("Generated", 1)
	return ns.encrypt(latest)
}

// minUsed returns the lowest key in the used map. Requires that a lock be held
// by caller.
func (ns *NonceService) minUsed() int64 {
	s := time.Now()
	min := ns.latest
	for t := range ns.used {
		if t < min {
			min = t
		}
	}
	ns.stats.TimingDuration("LinearScan.Latency", time.Since(s))
	return min
}

// Valid determines whether the provided Nonce string is valid, returning
// true if so.
func (ns *NonceService) Valid(nonce string) bool {
	c, err := ns.decrypt(nonce)
	if err != nil {
		ns.stats.Inc("Invalid.Decrypt", 1)
		return false
	}

	ns.mu.Lock()
	defer ns.mu.Unlock()
	if c > ns.latest {
		ns.stats.Inc("Invalid.TooHigh", 1)
		return false
	}

	if c <= ns.earliest {
		ns.stats.Inc("Invalid.TooLow", 1)
		return false
	}

	if ns.used[c] {
		ns.stats.Inc("Invalid.AlreadyUsed", 1)
		return false
	}

	ns.used[c] = true
	if len(ns.used) > ns.maxUsed {
		ns.stats.Inc("LinearScan.Full", 1)
		ns.earliest = ns.minUsed()
		delete(ns.used, ns.earliest)
	}

	ns.stats.Inc("Valid", 1)
	return true
}
