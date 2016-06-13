package grpc

import (
	"testing"
	"time"

	"google.golang.org/grpc/naming"

	"github.com/letsencrypt/boulder/test"
)

func TestStaticResolver(t *testing.T) {
	names := []string{"test:443"}
	sr := newStaticResolver(names)
	watcher, err := sr.Resolve("")
	test.AssertNotError(t, err, "staticResolver.Resolve failed")

	// Make sure doing this doesn't break anything (since it does nothing)
	watcher.Close()

	updates, err := watcher.Next()
	test.AssertNotError(t, err, "staticwatcher.Next failed")
	test.AssertEquals(t, len(names), len(updates))
	test.AssertEquals(t, updates[0].Addr, "test:443")
	test.AssertEquals(t, updates[0].Op, naming.Add)
	test.AssertEquals(t, updates[0].Metadata, nil)

	returned := make(chan struct{}, 1)
	go func() {
		_, err = watcher.Next()
		test.AssertNotError(t, err, "watcher.Next failed")
		returned <- struct{}{}
	}()
	select {
	case <-returned:
		t.Fatal("staticWatcher.Next returned something after the first call")
	case <-time.After(time.Millisecond * 500):
	}
}
