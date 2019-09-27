package web

import (
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestStripDefaultSchemePort(t *testing.T) {
	host := StripDefaultSchemePort("https", "localhost:443")
	test.AssertEquals(t, host, "localhost")
	host = StripDefaultSchemePort("http", "localhost:80")
	test.AssertEquals(t, host, "localhost")
	host = StripDefaultSchemePort("https", "localhost:123")
	test.AssertEquals(t, host, "localhost:123")
}
