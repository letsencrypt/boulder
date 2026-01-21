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
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	berrors "github.com/letsencrypt/boulder/errors"
	noncepb "github.com/letsencrypt/boulder/nonce/proto"
)

const (
	// PrefixLen is the character length of a nonce prefix.
	PrefixLen = 8

	// NonceLen is the character length of a nonce, excluding the prefix.
	NonceLen       = 32
	defaultMaxUsed = 65536
)

var errInvalidNonceLength = fmt.Errorf("invalid nonce length")

// PrefixCtxKey is exported for use as a key in a context.Context.
type PrefixCtxKey struct{}

// HMACKeyCtxKey is exported for use as a key in a context.Context.
type HMACKeyCtxKey struct{}

// DerivePrefix derives a nonce prefix from the provided listening address and
// key. The prefix is derived by take the first 8 characters of the base64url
// encoded HMAC-SHA256 hash of the listening address using the provided key.
func DerivePrefix(grpcAddr string, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(grpcAddr))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))[:PrefixLen]
}

// NonceService generates, cancels, and tracks Nonces.
type NonceService struct {
	noncepb.UnsafeNonceServiceServer
	mu               sync.Mutex
	latest           int64
	earliest         int64
	used             map[int64]bool
	usedHeap         *int64Heap
	gcm              cipher.AEAD
	maxUsed          int
	prefix           string
	nonceCreates     prometheus.Counter
	nonceEarliest    prometheus.Gauge
	nonceLatest      prometheus.Gauge
	nonceRedeems     *prometheus.CounterVec
	nonceAges        *prometheus.HistogramVec
	nonceHeapLatency prometheus.Histogram
}

type int64Heap []int64

func (h int64Heap) Len() int           { return len(h) }
func (h int64Heap) Less(i, j int) bool { return h[i] < h[j] }
func (h int64Heap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *int64Heap) Push(x any) {
	*h = append(*h, x.(int64))
}

func (h *int64Heap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

// NewNonceService constructs a NonceService with defaults
func NewNonceService(stats prometheus.Registerer, maxUsed int, prefix string) (*NonceService, error) {
	// If a prefix is provided it must be eight characters and valid base64. The
	// prefix is required to be base64url as RFC8555 section 6.5.1 requires that
	// nonces use that encoding. As base64 operates on three byte binary segments
	// we require the prefix to be six bytes (eight characters) so that the bytes
	// preceding the prefix wouldn't impact the encoding.
	if prefix != "" {
		if len(prefix) != PrefixLen {
			return nil, fmt.Errorf(
				"nonce prefix must be %d characters, not %d",
				PrefixLen,
				len(prefix),
			)
		}
		if _, err := base64.RawURLEncoding.DecodeString(prefix); err != nil {
			return nil, fmt.Errorf("nonce prefix must be valid base64url")
		}
	}

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

	if maxUsed <= 0 {
		maxUsed = defaultMaxUsed
	}

	nonceCreates := promauto.With(stats).NewCounter(prometheus.CounterOpts{
		Name: "nonce_creates",
		Help: "A counter of nonces generated",
	})
	nonceEarliest := promauto.With(stats).NewGauge(prometheus.GaugeOpts{
		Name: "nonce_earliest",
		Help: "A gauge with the current earliest valid nonce value",
	})
	nonceLatest := promauto.With(stats).NewGauge(prometheus.GaugeOpts{
		Name: "nonce_latest",
		Help: "A gauge with the current latest valid nonce value",
	})
	nonceRedeems := promauto.With(stats).NewCounterVec(prometheus.CounterOpts{
		Name: "nonce_redeems",
		Help: "A counter of nonce validations labelled by result",
	}, []string{"result", "error"})
	nonceAges := promauto.With(stats).NewHistogramVec(prometheus.HistogramOpts{
		Name:    "nonce_ages",
		Help:    "A histogram of nonce ages at the time they were (attempted to be) redeemed, expressed as fractions of the valid nonce window",
		Buckets: []float64{-0.01, 0, .1, .2, .3, .4, .5, .6, .7, .8, .9, 1, 1.1, 1.2, 1.5, 2, 5},
	}, []string{"result"})
	nonceHeapLatency := promauto.With(stats).NewHistogram(prometheus.HistogramOpts{
		Name: "nonce_heap_latency",
		Help: "A histogram of latencies of heap pop operations",
	})

	return &NonceService{
		earliest:         0,
		latest:           0,
		used:             make(map[int64]bool, maxUsed),
		usedHeap:         &int64Heap{},
		gcm:              gcm,
		maxUsed:          maxUsed,
		prefix:           prefix,
		nonceCreates:     nonceCreates,
		nonceEarliest:    nonceEarliest,
		nonceLatest:      nonceLatest,
		nonceRedeems:     nonceRedeems,
		nonceAges:        nonceAges,
		nonceHeapLatency: nonceHeapLatency,
	}, nil
}

func (ns *NonceService) encrypt(counter int64) (string, error) {
	// Generate a nonce with upper 4 bytes zero
	nonce := make([]byte, 12)
	for i := range 4 {
		nonce[i] = 0
	}
	_, err := rand.Read(nonce[4:])
	if err != nil {
		return "", err
	}

	// Encode counter to plaintext
	pt := make([]byte, 8)
	ctr := big.NewInt(counter)
	pad := 8 - len(ctr.Bytes())
	copy(pt[pad:], ctr.Bytes())

	// Encrypt
	ret := make([]byte, NonceLen)
	ct := ns.gcm.Seal(nil, nonce, pt, nil)
	copy(ret, nonce[4:])
	copy(ret[8:], ct)

	return ns.prefix + base64.RawURLEncoding.EncodeToString(ret), nil
}

func (ns *NonceService) decrypt(nonce string) (int64, error) {
	body := nonce
	if ns.prefix != "" {
		var prefix string
		var err error
		prefix, body, err = ns.splitNonce(nonce)
		if err != nil {
			return 0, err
		}
		if ns.prefix != prefix {
			return 0, fmt.Errorf("nonce contains invalid prefix: expected %q, got %q", ns.prefix, prefix)
		}
	}
	decoded, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return 0, err
	}
	if len(decoded) != NonceLen {
		return 0, errInvalidNonceLength
	}

	n := make([]byte, 12)
	for i := range 4 {
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

// nonce provides a new Nonce.
func (ns *NonceService) nonce() (string, error) {
	ns.mu.Lock()
	ns.latest++
	latest := ns.latest
	ns.mu.Unlock()
	ns.nonceCreates.Inc()
	ns.nonceLatest.Set(float64(latest))
	return ns.encrypt(latest)
}

// valid determines whether the provided Nonce string is valid, returning
// true if so.
func (ns *NonceService) valid(nonce string) error {
	c, err := ns.decrypt(nonce)
	if err != nil {
		ns.nonceRedeems.WithLabelValues("invalid", "decrypt").Inc()
		return berrors.BadNonceError("unable to decrypt nonce: %s", err)
	}

	ns.mu.Lock()
	defer ns.mu.Unlock()

	// age represents how "far back" in the valid nonce window this nonce is.
	// If it is very recent, then the numerator is very small and the age is close
	// to zero. If it is old but still valid, the numerator is slightly smaller
	// than the denominator, and the age is close to one. If it is too old, then
	// the age is greater than one. If it is magically too new (i.e. greater than
	// the largest nonce we've actually handed out), then the age is negative.
	age := float64(ns.latest-c) / float64(ns.latest-ns.earliest)

	if c > ns.latest { // i.e. age < 0
		ns.nonceRedeems.WithLabelValues("invalid", "too high").Inc()
		ns.nonceAges.WithLabelValues("invalid").Observe(age)
		return berrors.BadNonceError("nonce greater than highest dispensed nonce: %d > %d", c, ns.latest)
	}

	if c <= ns.earliest { // i.e. age >= 1
		ns.nonceRedeems.WithLabelValues("invalid", "too low").Inc()
		ns.nonceAges.WithLabelValues("invalid").Observe(age)
		return berrors.BadNonceError("nonce less than lowest eligible nonce: %d < %d", c, ns.earliest)
	}

	if ns.used[c] {
		ns.nonceRedeems.WithLabelValues("invalid", "already used").Inc()
		ns.nonceAges.WithLabelValues("invalid").Observe(age)
		return berrors.BadNonceError("nonce already marked as used: %d in [%d]used", c, len(ns.used))
	}

	ns.used[c] = true
	heap.Push(ns.usedHeap, c)
	if len(ns.used) > ns.maxUsed {
		s := time.Now()
		ns.earliest = heap.Pop(ns.usedHeap).(int64)
		ns.nonceEarliest.Set(float64(ns.earliest))
		ns.nonceHeapLatency.Observe(time.Since(s).Seconds())
		delete(ns.used, ns.earliest)
	}

	ns.nonceRedeems.WithLabelValues("valid", "").Inc()
	ns.nonceAges.WithLabelValues("valid").Observe(age)
	return nil
}

// splitNonce splits a nonce into a prefix and a body.
func (ns *NonceService) splitNonce(nonce string) (string, string, error) {
	if len(nonce) < PrefixLen {
		return "", "", errInvalidNonceLength
	}
	return nonce[:PrefixLen], nonce[PrefixLen:], nil
}

// Redeem accepts a nonce from a gRPC client and redeems it using the inner nonce service.
func (ns *NonceService) Redeem(ctx context.Context, msg *noncepb.NonceMessage) (*noncepb.ValidMessage, error) {
	err := ns.valid(msg.Nonce)
	if err != nil {
		return nil, err
	}
	return &noncepb.ValidMessage{Valid: true}, nil
}

// Nonce generates a nonce and sends it to a gRPC client.
func (ns *NonceService) Nonce(_ context.Context, _ *emptypb.Empty) (*noncepb.NonceMessage, error) {
	nonce, err := ns.nonce()
	if err != nil {
		return nil, err
	}
	return &noncepb.NonceMessage{Nonce: nonce}, nil
}

// Getter is an interface for an RPC client that can get a nonce.
type Getter interface {
	Nonce(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*noncepb.NonceMessage, error)
}

// Redeemer is an interface for an RPC client that can redeem a nonce.
type Redeemer interface {
	Redeem(ctx context.Context, in *noncepb.NonceMessage, opts ...grpc.CallOption) (*noncepb.ValidMessage, error)
}

// NewGetter returns a new noncepb.NonceServiceClient which can only be used to
// get nonces.
func NewGetter(cc grpc.ClientConnInterface) Getter {
	return noncepb.NewNonceServiceClient(cc)
}

// NewRedeemer returns a new noncepb.NonceServiceClient which can only be used
// to redeem nonces.
func NewRedeemer(cc grpc.ClientConnInterface) Redeemer {
	return noncepb.NewNonceServiceClient(cc)
}
