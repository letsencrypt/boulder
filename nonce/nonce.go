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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash"
	"strconv"
	"strings"
	"sync"
	"time"

	noncepb "github.com/letsencrypt/boulder/nonce/proto"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	defaultMaxUsed = 65536
	nonceLen       = 32
)

var errInvalidNonceLength = errors.New("invalid nonce length")

// NonceService generates, cancels, and tracks Nonces.
type NonceService struct {
	mu               sync.Mutex
	latest           uint64
	earliest         uint64
	used             map[uint64]bool
	usedHeap         *uint64Heap
	key              []byte
	maxUsed          int
	prefix           string
	nonceCreates     prometheus.Counter
	nonceRedeems     *prometheus.CounterVec
	nonceHeapLatency prometheus.Histogram
}

type uint64Heap []uint64

func (h uint64Heap) Len() int           { return len(h) }
func (h uint64Heap) Less(i, j int) bool { return h[i] < h[j] }
func (h uint64Heap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *uint64Heap) Push(x interface{}) {
	*h = append(*h, x.(uint64))
}

func (h *uint64Heap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

// NewNonceService constructs a NonceService with defaults
func NewNonceService(stats prometheus.Registerer, maxUsed int, prefix string) (*NonceService, error) {
	// If a prefix is provided it must be four characters and valid
	// base64. The prefix is required to be base64url as RFC8555
	// section 6.5.1 requires that nonces use that encoding.
	// As base64 operates on three byte binary segments we require
	// the prefix to be three bytes (four characters) so that the
	// bytes preceding the prefix wouldn't impact the encoding.
	if prefix != "" {
		if len(prefix) != 4 {
			return nil, errors.New("nonce prefix must be 4 characters")
		}
		if _, err := base64.RawURLEncoding.DecodeString(prefix); err != nil {
			return nil, errors.New("nonce prefix must be valid base64url")
		}
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	if maxUsed <= 0 {
		maxUsed = defaultMaxUsed
	}

	nonceCreates := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "nonce_creates",
		Help: "A counter of nonces generated",
	})
	stats.MustRegister(nonceCreates)
	nonceRedeems := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "nonce_redeems",
		Help: "A counter of nonce validations labelled by result",
	}, []string{"result", "error"})
	stats.MustRegister(nonceRedeems)
	nonceHeapLatency := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "nonce_heap_latency",
		Help: "A histogram of latencies of heap pop operations",
	})
	stats.MustRegister(nonceHeapLatency)

	return &NonceService{
		earliest:         0,
		latest:           0,
		used:             make(map[uint64]bool, maxUsed),
		usedHeap:         &uint64Heap{},
		key:              key,
		maxUsed:          maxUsed,
		prefix:           prefix,
		nonceCreates:     nonceCreates,
		nonceRedeems:     nonceRedeems,
		nonceHeapLatency: nonceHeapLatency,
	}, nil
}

func (ns *NonceService) createHMAC() hash.Hash {
	return hmac.New(sha256.New, ns.key)
}

func (ns *NonceService) mac(counter uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, counter)

	// mac it
	mac := ns.createHMAC()
	mac.Write(b)
	return mac.Sum(nil)
}

// Nonce provides a new Nonce.
func (ns *NonceService) Nonce() (string, error) {
	sb := strings.Builder{}
	ns.mu.Lock()
	ns.latest++
	latest := ns.latest
	ns.mu.Unlock()

	defer ns.nonceCreates.Inc()

	sb.WriteString(ns.prefix)
	sb.WriteString(",")

	sb.WriteString(strconv.FormatUint(latest, 10))
	sb.WriteString(",")
	sb.WriteString(base64.RawURLEncoding.EncodeToString(ns.mac(latest)))

	return sb.String(), nil
}

// Valid determines whether the provided Nonce string is valid, returning
// true if so.
func (ns *NonceService) Valid(nonce string) bool {
	prefix, c, mac, err := splitNonce(nonce)
	if ns.prefix != prefix {
		ns.nonceRedeems.WithLabelValues("invalid", "prefix").Inc()
		return false
	}
	if err != nil {
		ns.nonceRedeems.WithLabelValues("invalid", "split").Inc()
		return false
	}

	expected := ns.mac(c)
	if subtle.ConstantTimeCompare(expected, mac) != 1 {
		ns.nonceRedeems.WithLabelValues("invalid", "hmac").Inc()
		return false
	}

	ns.mu.Lock()
	defer ns.mu.Unlock()
	if c > ns.latest {
		ns.nonceRedeems.WithLabelValues("invalid", "too high").Inc()
		return false
	}

	if c <= ns.earliest {
		ns.nonceRedeems.WithLabelValues("invalid", "too low").Inc()
		return false
	}

	if ns.used[c] {
		ns.nonceRedeems.WithLabelValues("invalid", "already used").Inc()
		return false
	}

	ns.used[c] = true
	heap.Push(ns.usedHeap, c)
	if len(ns.used) > ns.maxUsed {
		s := time.Now()
		ns.earliest = heap.Pop(ns.usedHeap).(uint64)
		ns.nonceHeapLatency.Observe(time.Since(s).Seconds())
		delete(ns.used, ns.earliest)
	}

	ns.nonceRedeems.WithLabelValues("valid", "").Inc()
	return true
}

// RemoteRedeem checks the nonce prefix and routes the Redeem RPC
// to the associated remote nonce service
func RemoteRedeem(ctx context.Context, noncePrefixMap map[string]noncepb.NonceServiceClient, nonce string) (bool, error) {
	prefix, _, _, err := splitNonce(nonce)
	if err != nil {
		return false, nil
	}
	nonceService, present := noncePrefixMap[prefix]
	if !present {
		return false, nil
	}
	resp, err := nonceService.Redeem(ctx, &noncepb.NonceMessage{Nonce: nonce})
	if err != nil {
		return false, err
	}
	return resp.Valid, nil
}

func splitNonce(nonce string) (prefix string, number uint64, mac []byte, err error) {
	split := strings.Split(nonce, ",")
	if len(split) != 3 {
		err = errInvalidNonceLength
		return
	}
	prefix = split[0]
	numberStr := split[1]
	macStr := split[2]

	mac, err = base64.RawURLEncoding.DecodeString(macStr)
	if err != nil {
		return
	}

	number, err = strconv.ParseUint(numberStr, 10, 64)
	if err != nil {
		return
	}

	err = nil
	return
}
