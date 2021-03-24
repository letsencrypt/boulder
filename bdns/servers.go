package bdns

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"
)

// serverProvider represents a type which can provide a list of addresses for
// the bdns to use as DNS resolvers. Different implementations may provide
// different strategies for providing addresses, and may provide different kinds
// of addresses (e.g. host:port combos vs IP addresses).
type ServerProvider interface {
	Addrs() ([]string, error)
	Stop()
}

// staticProvider stores a list of host:port combos, and provides that whole
// list in randomized order when asked for addresses. This replicates the old
// behavior of the bdns.impl's servers field.
type staticProvider struct {
	servers []string
}

var _ ServerProvider = &staticProvider{}

func NewStaticProvider(servers []string) *staticProvider {
	return &staticProvider{servers: servers}
}

func (sp *staticProvider) Addrs() ([]string, error) {
	if sp.servers == nil || len(sp.servers) == 0 {
		return nil, fmt.Errorf("no servers configured")
	}
	r := make([]string, len(sp.servers))
	perm := rand.Perm(len(sp.servers))
	for i, v := range perm {
		r[i] = sp.servers[v]
	}
	return r, nil
}

func (sp *staticProvider) Stop() {}

// dynamicProvider uses DNS to look up the set of IP addresses which correspond
// to its single host. It returns this list in random order when asked for
// addresses, and refreshes it regularly using a goroutine started by its
// constructor.
type dynamicProvider struct {
	host   string
	addrs  map[string][]uint16
	mut    sync.RWMutex
	cancel chan interface{}
}

var _ ServerProvider = &dynamicProvider{}

// StartDynamicProvider constructs a new dynamicProvider and starts its
// auto-update goroutine. The auto-update process queries DNS for SRV records
// at refresh intervals and uses the resulting IP/port combos to populate the
// list returned by Addrs. The update process ignores the Priority and Weight
// attributes of the SRV records.
func StartDynamicProvider(server string, refresh time.Duration) (*dynamicProvider, error) {
	if server == "" {

	}
	dp := dynamicProvider{
		host:   server,
		addrs:  make(map[string][]uint16),
		mut:    sync.RWMutex{},
		cancel: make(chan interface{}),
	}
	err := dp.update()
	if err != nil {
		return nil, fmt.Errorf("failed to start dynamic provider: %w", err)
	}

	go func() {
		t := time.NewTicker(refresh)
		for {
			select {
			case <-t.C:
				err := dp.update()
				if err != nil {
					continue
				}
			case <-dp.cancel:
				return
			}
		}
	}()

	return &dp, nil
}

func (dp *dynamicProvider) update() error {
	_, srvs, err := net.LookupSRV(dp.host, "", "")
	if err != nil {
		return err
	}
	if srvs == nil || len(srvs) == 0 {
		return fmt.Errorf("failed to find SRV records for: %q", dp.host)
	}

	addrs := make(map[string][]uint16)
	for _, srv := range srvs {
		addrs[srv.Target] = append(addrs[srv.Target], srv.Port)
	}

	dp.mut.Lock()
	dp.addrs = addrs
	dp.mut.Unlock()
	return nil
}

// Addrs returns a shuffled list of IP/port pairs, with the guarantee that no
// two IP/port pairs will share the same IP.
func (dp *dynamicProvider) Addrs() ([]string, error) {
	var r []string
	dp.mut.RLock()
	for ip, ports := range dp.addrs {
		port := ports[rand.Intn(len(ports))]
		addr := fmt.Sprintf("%s:%d", ip, port)
		r = append(r, addr)
	}
	dp.mut.RUnlock()
	rand.Shuffle(len(r), func(i, j int) {
		r[i], r[j] = r[j], r[i]
	})
	return r, nil
}

func (dp *dynamicProvider) Stop() {
	close(dp.cancel)
}
