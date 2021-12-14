package wfe2

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/golang/groupcache/lru"
	"github.com/jmhodges/clock"
	corepb "github.com/letsencrypt/boulder/core/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// AccountGetter represents the ability to get an account by ID - either from the SA
// or from a cache.
type AccountGetter interface {
	GetRegistration(ctx context.Context, regID *sapb.RegistrationID, opts ...grpc.CallOption) (*corepb.Registration, error)
}

// accountCache is an implementation of accountGetter that first tries a local
// in-memory cache, and if the account is not there, calls out to an underlying
// accountGetter. It is safe for concurrent access so long as the underlying
// accountGetter is.
type accountCache struct {
	sync.RWMutex
	under AccountGetter
	ttl   time.Duration
	cache *lru.Cache
	clk   clock.Clock
}

func NewAccountCache(under AccountGetter, maxEntries int, ttl time.Duration, clk clock.Clock) *accountCache {
	return &accountCache{
		under: under,
		ttl:   ttl,
		cache: lru.New(maxEntries),
		clk:   clk,
	}
}

type accountEntry struct {
	account *corepb.Registration
	expires time.Time
}

func (ac *accountCache) GetRegistration(ctx context.Context, regID *sapb.RegistrationID, opts ...grpc.CallOption) (*corepb.Registration, error) {
	ac.RLock()
	val, ok := ac.cache.Get(regID.Id)
	ac.RUnlock()
	if !ok {
		return ac.queryAndStore(ctx, regID)
	}
	entry, ok := val.(accountEntry)
	if !ok {
		return nil, fmt.Errorf("shouldn't happen: wrong type %T for cache entry", entry)
	}
	if entry.expires.After(ac.clk.Now()) {
		// Note: this has a slight TOCTOU issue but it's benign. If the entry for this account
		// was expired off by some other goroutine and then a fresh one added, removing it a second
		// time will just cause a slightly lower cache rate.
		// We have to actively remove expired entries, because otherwise each retrieval counts as
		// a "use" and they won't exit the cache on their own.
		ac.Lock()
		ac.cache.Remove(regID.Id)
		ac.Unlock()
		return ac.queryAndStore(ctx, regID)
	}
	copied := new(corepb.Registration)
	proto.Merge(copied, entry.account)
	return copied, nil
}

func (ac *accountCache) queryAndStore(ctx context.Context, regID *sapb.RegistrationID) (*corepb.Registration, error) {
	account, err := ac.under.GetRegistration(ctx, regID)
	if err != nil {
		return nil, err
	}
	ac.Lock()
	ac.cache.Add(regID.Id, accountEntry{
		account: account,
		expires: ac.clk.Now().Add(ac.ttl),
	})
	ac.Unlock()
	copied := new(corepb.Registration)
	proto.Merge(copied, account)
	return copied, nil
}
