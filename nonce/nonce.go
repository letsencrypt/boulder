// Package nonce implements a service for generating and redeeming nonces.
// To generate a nonce, it encrypts a monotonically increasing counter (latest)
// using an authenticated cipher. To redeem a nonce, it checks that the nonce
// decrypts to a valid integer between the earliest and latest counter values,
// and that it's not on the cross-off list. To avoid a constantly growing cross-off
// list, the nonce service periodically retires the oldest counter values by
// finding the lowest counter value in the cross-off list, deleting it, and setting
// "earliest" to its value. To make this efficient, the cross-off list is represented
// two ways: Once as a map, for quick lookup of a given value, and once as a heap,
// to quickly find the lowest value.
// The MaxUsed value determines how long a generated nonce can be used before it
// is forgotten. To calculate that period, divide the MaxUsed value by average
// redemption rate (valid POSTs per second).
package nonce

import (
	"container/heap"
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
	usedHeap *int64Heap
	gcm      cipher.AEAD
	maxUsed  int
	stats    metrics.Scope
}

type int64Heap []int64

func (h int64Heap) Len() int           { return len(h) }
func (h int64Heap) Less(i, j int) bool { return h[i] < h[j] }
func (h int64Heap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *int64Heap) Push(x interface{}) {
	*h = append(*h, x.(int64))
}

func (h *int64Heap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

// NewNonceService constructs a NonceService with defaults
func NewNonceService(scope metrics.Scope) (*NonceService, error) {
	scope = scope.NewScope("NonceService")
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
		usedHeap: &int64Heap{},
		gcm:      gcm,
		maxUsed:  MaxUsed,
		stats:    scope,
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
	heap.Push(ns.usedHeap, c)
	if len(ns.used) > ns.maxUsed {
		s := time.Now()
		ns.earliest = heap.Pop(ns.usedHeap).(int64)
		ns.stats.TimingDuration("Heap.Latency", time.Since(s))
		delete(ns.used, ns.earliest)
	}

	ns.stats.Inc("Valid", 1)
	return true
}
