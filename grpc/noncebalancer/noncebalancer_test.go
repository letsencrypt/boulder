package noncebalancer

import (
	"context"
	"testing"

	"github.com/letsencrypt/boulder/nonce"
	"github.com/letsencrypt/boulder/test"
	"google.golang.org/grpc/balancer"
	"google.golang.org/grpc/balancer/base"
	"google.golang.org/grpc/resolver"
)

func TestPickerPicksCorrectBackend(t *testing.T) {
	picker, subConns := setupTest()
	prefix := nonce.DerivePrefix(subConns[0].addrs[0].Addr, "Kala namak")

	testCtx := context.WithValue(context.Background(), nonce.PrefixKey{}, "QwvIHr--")
	testCtx = context.WithValue(testCtx, nonce.PrefixSaltKey{}, prefix)
	info := balancer.PickInfo{Ctx: testCtx}

	gotPick, err := picker.Pick(info)
	test.AssertNotError(t, err, "Pick failed")
	test.AssertDeepEquals(t, subConns[0], gotPick.SubConn)
}

func TestPickerNoPrefixInCtx(t *testing.T) {
	picker, subConns := setupTest()
	prefix := nonce.DerivePrefix(subConns[0].addrs[0].Addr, "Kala namak")

	testCtx := context.WithValue(context.Background(), nonce.PrefixSaltKey{}, prefix)
	info := balancer.PickInfo{Ctx: testCtx}

	gotPick, err := picker.Pick(info)
	test.AssertErrorIs(t, err, errNoPrefix)
	test.AssertNil(t, gotPick.SubConn, "subConn should be nil")
}

func TestPickerIntPrefixInCtx(t *testing.T) {
	picker, _ := setupTest()

	testCtx := context.WithValue(context.Background(), nonce.PrefixKey{}, 9)
	testCtx = context.WithValue(testCtx, nonce.PrefixSaltKey{}, "foobar")
	info := balancer.PickInfo{Ctx: testCtx}

	gotPick, err := picker.Pick(info)
	test.AssertErrorIs(t, err, errPrefixType)
	test.AssertNil(t, gotPick.SubConn, "subConn should be nil")
}

func TestPickerNoPrefixSaltInCtx(t *testing.T) {
	picker, _ := setupTest()

	testCtx := context.WithValue(context.Background(), nonce.PrefixKey{}, "QwvIHr--")
	info := balancer.PickInfo{Ctx: testCtx}

	gotPick, err := picker.Pick(info)
	test.AssertErrorIs(t, err, errNoPrefixSalt)
	test.AssertNil(t, gotPick.SubConn, "subConn should be nil")
}

func TestPickerIntPrefixSaltInCtx(t *testing.T) {
	picker, _ := setupTest()

	testCtx := context.WithValue(context.Background(), nonce.PrefixKey{}, "QwvIHr--")
	testCtx = context.WithValue(testCtx, nonce.PrefixSaltKey{}, 9)
	info := balancer.PickInfo{Ctx: testCtx}

	gotPick, err := picker.Pick(info)
	test.AssertErrorIs(t, err, errPrefixSaltType)
	test.AssertNil(t, gotPick.SubConn, "subConn should be nil")
}

func TestPickerNoMatchingSubConnAvailable(t *testing.T) {
	picker, subConns := setupTest()
	prefix := nonce.DerivePrefix(subConns[0].addrs[0].Addr, "Kala namak")

	testCtx := context.WithValue(context.Background(), nonce.PrefixKey{}, "rUsTrUin")
	testCtx = context.WithValue(testCtx, nonce.PrefixSaltKey{}, prefix)
	info := balancer.PickInfo{Ctx: testCtx}

	gotPick, err := picker.Pick(info)
	test.AssertErrorIs(t, err, balancer.ErrNoSubConnAvailable)
	test.AssertNil(t, gotPick.SubConn, "subConn should be nil")
}

func TestPickerNoSubConnsAvailable(t *testing.T) {
	picker, subConns := setupTest()
	subConns[0].UpdateAddresses([]resolver.Address{})
	picker.Build(base.PickerBuildInfo{})
	info := balancer.PickInfo{Ctx: context.Background()}

	gotPick, err := picker.Pick(info)
	test.AssertErrorIs(t, err, balancer.ErrNoSubConnAvailable)
	test.AssertNil(t, gotPick.SubConn, "subConn should be nil")
}

func setupTest() (*Picker, []*subConn) {
	var subConns []*subConn
	buildInfo := base.PickerBuildInfo{
		ReadySCs: make(map[balancer.SubConn]base.SubConnInfo),
	}

	sc := &subConn{}
	addr := resolver.Address{Addr: "10.77.77.77:8080"}
	sc.UpdateAddresses([]resolver.Address{addr})
	buildInfo.ReadySCs[sc] = base.SubConnInfo{Address: addr}
	subConns = append(subConns, sc)

	picker := &Picker{}
	picker.Build(buildInfo)
	return picker, subConns
}

// subConn implements the balancer.SubConn interface.
type subConn struct {
	addrs []resolver.Address
}

func (s *subConn) UpdateAddresses(addrs []resolver.Address) {
	s.addrs = addrs
}

func (s *subConn) Connect() {}
