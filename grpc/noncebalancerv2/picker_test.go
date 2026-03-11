package noncebalancerv2

import (
	"context"
	"testing"

	"google.golang.org/grpc/balancer"
	"google.golang.org/grpc/resolver"

	"github.com/letsencrypt/boulder/nonce"
	"github.com/letsencrypt/boulder/test"
)

func TestPickerPicksCorrectBackend(t *testing.T) {
	sc, p := setupTestPicker(t)

	hmacKey := []byte("Kala namak")
	prefix := nonce.DerivePrefix(sc.addrs[0].Addr, hmacKey)

	testCtx := context.WithValue(context.Background(), nonce.PrefixCtxKey{}, prefix)
	testCtx = context.WithValue(testCtx, nonce.HMACKeyCtxKey{}, hmacKey)
	info := balancer.PickInfo{Ctx: testCtx}

	gotPick, err := p.Pick(info)
	test.AssertNotError(t, err, "Pick failed")
	test.AssertDeepEquals(t, sc, gotPick.SubConn)
}

func TestPickerMissingPrefixInCtx(t *testing.T) {
	_, p := setupTestPicker(t)

	testCtx := context.WithValue(context.Background(), nonce.HMACKeyCtxKey{}, []byte("Kala namak"))
	info := balancer.PickInfo{Ctx: testCtx}

	gotPick, err := p.Pick(info)
	test.AssertErrorIs(t, err, errMissingPrefixCtxKey)
	test.AssertNil(t, gotPick.SubConn, "subConn should be nil")
}

func TestPickerInvalidPrefixInCtx(t *testing.T) {
	_, p := setupTestPicker(t)

	testCtx := context.WithValue(context.Background(), nonce.PrefixCtxKey{}, 9)
	testCtx = context.WithValue(testCtx, nonce.HMACKeyCtxKey{}, []byte("foobar"))
	info := balancer.PickInfo{Ctx: testCtx}

	gotPick, err := p.Pick(info)
	test.AssertErrorIs(t, err, errInvalidPrefixCtxKeyType)
	test.AssertNil(t, gotPick.SubConn, "subConn should be nil")
}

func TestPickerMissingHMACKeyInCtx(t *testing.T) {
	_, p := setupTestPicker(t)

	testCtx := context.WithValue(context.Background(), nonce.PrefixCtxKey{}, "HNmOnt8w")
	info := balancer.PickInfo{Ctx: testCtx}

	gotPick, err := p.Pick(info)
	test.AssertErrorIs(t, err, errMissingHMACKeyCtxKey)
	test.AssertNil(t, gotPick.SubConn, "subConn should be nil")
}

func TestPickerInvalidHMACKeyInCtx(t *testing.T) {
	_, p := setupTestPicker(t)

	testCtx := context.WithValue(context.Background(), nonce.PrefixCtxKey{}, "HNmOnt8w")
	testCtx = context.WithValue(testCtx, nonce.HMACKeyCtxKey{}, 9)
	info := balancer.PickInfo{Ctx: testCtx}

	gotPick, err := p.Pick(info)
	test.AssertErrorIs(t, err, errInvalidHMACKeyCtxKeyType)
	test.AssertNil(t, gotPick.SubConn, "subConn should be nil")
}

func TestPickerUnknownPrefix(t *testing.T) {
	_, p := setupTestPicker(t)

	hmacKey := []byte("Kala namak")

	testCtx := context.WithValue(context.Background(), nonce.PrefixCtxKey{}, "rUsTrUin")
	testCtx = context.WithValue(testCtx, nonce.HMACKeyCtxKey{}, hmacKey)
	info := balancer.PickInfo{Ctx: testCtx}

	gotPick, err := p.Pick(info)
	test.AssertErrorIs(t, err, ErrNoBackendsMatchPrefix.Err())
	test.AssertNil(t, gotPick.SubConn, "subConn should be nil")
}

func TestPickerSubConnReconnecting(t *testing.T) {
	sc := &subConn{}
	addr := resolver.Address{Addr: "10.77.77.77:8080"}
	sc.UpdateAddresses([]resolver.Address{addr})

	hmacKey := []byte("Kala namak")
	prefix := nonce.DerivePrefix(addr.Addr, hmacKey)

	// Build a picker where the SubConn is known but not READY.
	p := &picker{
		readyBackends:    map[balancer.SubConn]resolver.Address{},
		notReadyBackends: map[balancer.SubConn]resolver.Address{sc: addr},
	}

	testCtx := context.WithValue(context.Background(), nonce.PrefixCtxKey{}, prefix)
	testCtx = context.WithValue(testCtx, nonce.HMACKeyCtxKey{}, hmacKey)
	info := balancer.PickInfo{Ctx: testCtx}

	// Should return ErrNoSubConnAvailable (queue the RPC) not
	// ErrNoBackendsMatchPrefix (fail the RPC).
	gotPick, err := p.Pick(info)
	test.AssertErrorIs(t, err, balancer.ErrNoSubConnAvailable)
	test.AssertNil(t, gotPick.SubConn, "subConn should be nil")
}

func TestPickerSubConnBecomesReady(t *testing.T) {
	sc := &subConn{}
	addr := resolver.Address{Addr: "10.77.77.77:8080"}
	sc.UpdateAddresses([]resolver.Address{addr})

	hmacKey := []byte("Kala namak")
	prefix := nonce.DerivePrefix(addr.Addr, hmacKey)

	// First picker: SubConn is not READY.
	p1 := &picker{
		readyBackends:    map[balancer.SubConn]resolver.Address{},
		notReadyBackends: map[balancer.SubConn]resolver.Address{sc: addr},
	}

	testCtx := context.WithValue(context.Background(), nonce.PrefixCtxKey{}, prefix)
	testCtx = context.WithValue(testCtx, nonce.HMACKeyCtxKey{}, hmacKey)
	info := balancer.PickInfo{Ctx: testCtx}

	_, err := p1.Pick(info)
	test.AssertErrorIs(t, err, balancer.ErrNoSubConnAvailable)

	// Second picker: SubConn is now READY (simulates picker rebuild after
	// SubConn reconnects).
	p2 := &picker{
		readyBackends:    map[balancer.SubConn]resolver.Address{sc: addr},
		notReadyBackends: map[balancer.SubConn]resolver.Address{},
	}

	gotPick, err := p2.Pick(info)
	test.AssertNotError(t, err, "Pick failed after SubConn became READY")
	test.AssertDeepEquals(t, sc, gotPick.SubConn)
}

// setupTestPicker creates a picker with a single READY SubConn for testing.
func setupTestPicker(t *testing.T) (*subConn, balancer.Picker) {
	t.Helper()

	sc := &subConn{}
	addr := resolver.Address{Addr: "10.77.77.77:8080"}
	sc.UpdateAddresses([]resolver.Address{addr})

	p := &picker{
		readyBackends:    map[balancer.SubConn]resolver.Address{sc: addr},
		notReadyBackends: map[balancer.SubConn]resolver.Address{},
	}
	return sc, p
}

// subConn is a test mock which implements the balancer.SubConn interface.
type subConn struct {
	balancer.SubConn
	addrs []resolver.Address
}

func (s *subConn) UpdateAddresses(addrs []resolver.Address) {
	s.addrs = addrs
}
