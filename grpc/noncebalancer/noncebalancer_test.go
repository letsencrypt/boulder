package noncebalancer

import (
	"context"
	"testing"

	"github.com/letsencrypt/boulder/nonce"
	"github.com/letsencrypt/boulder/test"
	"google.golang.org/grpc/balancer"
)

// mockPicker implements the balancer.Picker interface.
//
// In this test it's used to fill the role of a child picker.
type mockPicker struct {
	called bool
}

func (mp *mockPicker) Pick(info balancer.PickInfo) (balancer.PickResult, error) {
	mp.called = true
	return balancer.PickResult{}, nil
}

func TestPickerPicksCorrectBackend(t *testing.T) {
	addr1 := "10.77.77.77:8080"
	addr2 := "10.88.88.88:9090"
	prefix := nonce.DerivePrefix(addr1, []byte("Kala namak"))

	testCtx := context.WithValue(context.Background(), nonce.PrefixCtxKey{}, "HNmOnt8w")
	testCtx = context.WithValue(testCtx, nonce.HMACKeyCtxKey{}, []byte(prefix))
	info := balancer.PickInfo{Ctx: testCtx}

	childPicker1 := &mockPicker{}
	childPicker2 := &mockPicker{}

	p := newPicker(map[string]balancer.Picker{
		addr1: childPicker1,
		addr2: childPicker2,
	})

	_, err := p.Pick(info)
	if err != nil {
		t.Fatalf("Pick failed: %v", err)
	}

	if !childPicker1.called {
		t.Errorf("childPicker1 not called")
	}
	if childPicker2.called {
		t.Errorf("childPicker2 called, should not have been")
	}
}

func TestPickerMissingPrefixInCtx(t *testing.T) {
	p, addr := setupTest()
	prefix := nonce.DerivePrefix(addr, []byte("Kala namak"))

	testCtx := context.WithValue(context.Background(), nonce.HMACKeyCtxKey{}, []byte(prefix))
	info := balancer.PickInfo{Ctx: testCtx}

	gotPick, err := p.Pick(info)
	test.AssertErrorIs(t, err, errMissingPrefixCtxKey)
	test.AssertNil(t, gotPick.SubConn, "subConn should be nil")
}

func TestPickerInvalidPrefixInCtx(t *testing.T) {
	p, _ := setupTest()

	testCtx := context.WithValue(context.Background(), nonce.PrefixCtxKey{}, 9)
	testCtx = context.WithValue(testCtx, nonce.HMACKeyCtxKey{}, []byte("foobar"))
	info := balancer.PickInfo{Ctx: testCtx}

	gotPick, err := p.Pick(info)
	test.AssertErrorIs(t, err, errInvalidPrefixCtxKeyType)
	test.AssertNil(t, gotPick.SubConn, "subConn should be nil")
}

func TestPickerMissingHMACKeyInCtx(t *testing.T) {
	p, _ := setupTest()

	testCtx := context.WithValue(context.Background(), nonce.PrefixCtxKey{}, "HNmOnt8w")
	info := balancer.PickInfo{Ctx: testCtx}

	gotPick, err := p.Pick(info)
	test.AssertErrorIs(t, err, errMissingHMACKeyCtxKey)
	test.AssertNil(t, gotPick.SubConn, "subConn should be nil")
}

func TestPickerInvalidHMACKeyInCtx(t *testing.T) {
	p, _ := setupTest()

	testCtx := context.WithValue(context.Background(), nonce.PrefixCtxKey{}, "HNmOnt8w")
	testCtx = context.WithValue(testCtx, nonce.HMACKeyCtxKey{}, 9)
	info := balancer.PickInfo{Ctx: testCtx}

	gotPick, err := p.Pick(info)
	test.AssertErrorIs(t, err, errInvalidHMACKeyCtxKeyType)
	test.AssertNil(t, gotPick.SubConn, "subConn should be nil")
}

func TestPickerNoMatchingSubConnAvailable(t *testing.T) {
	p, addr := setupTest()
	prefix := nonce.DerivePrefix(addr, []byte("Kala namak"))

	testCtx := context.WithValue(context.Background(), nonce.PrefixCtxKey{}, "rUsTrUin")
	testCtx = context.WithValue(testCtx, nonce.HMACKeyCtxKey{}, []byte(prefix))
	info := balancer.PickInfo{Ctx: testCtx}

	gotPick, err := p.Pick(info)
	test.AssertErrorIs(t, err, ErrNoBackendsMatchPrefix.Err())
	test.AssertNil(t, gotPick.SubConn, "subConn should be nil")
}

func TestPickerNoSubConnsAvailable(t *testing.T) {
	p := newPicker(map[string]balancer.Picker{})
	info := balancer.PickInfo{Ctx: context.Background()}

	_, err := p.Pick(info)
	test.AssertErrorIs(t, err, balancer.ErrNoSubConnAvailable)
}

func setupTest() (*picker, string) {
	addr := "10.77.77.77:8080"
	p := newPicker(map[string]balancer.Picker{addr: &mockPicker{}})
	return p, addr
}
