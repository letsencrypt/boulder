package cdr

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/context"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/test"
)

var log = blog.UseMock()

func TestParseAnswer(t *testing.T) {
	as := []core.GPDNSAnswer{
		{Name: "a", Type: 257, TTL: 10, Data: "0 issue \"ca.com\""},
		{Name: "b", Type: 1, TTL: 10, Data: "1.1.1.1"},
	}

	r, err := parseAnswer(as)
	test.AssertNotError(t, err, "Failed to parse records")
	test.AssertEquals(t, len(r), 1)
	test.AssertEquals(t, r[0].Hdr.Name, "a.")
	test.AssertEquals(t, r[0].Hdr.Ttl, uint32(10))
	test.AssertEquals(t, r[0].Flag, uint8(0))
	test.AssertEquals(t, r[0].Tag, "issue")
	test.AssertEquals(t, r[0].Value, "ca.com")
}

func TestQueryCAA(t *testing.T) {
	testServ := httptest.NewServer(http.HandlerFunc(mocks.GPDNSHandler))
	defer testServ.Close()

	req, err := http.NewRequest("GET", testServ.URL, nil)
	test.AssertNotError(t, err, "Failed to create request")
	query := make(url.Values)
	query.Add("name", "test-domain")
	query.Add("type", "257") // CAA
	req.URL.RawQuery = query.Encode()

	client := new(http.Client)
	cpr := CAADistributedResolver{logger: log}
	set, err := cpr.queryCAA(context.Background(), testServ.URL+"?name=test-domain", client)
	test.AssertNotError(t, err, "queryCAA failed")
	test.AssertEquals(t, len(set), 1)
	test.AssertEquals(t, set[0].Hdr.Name, "test-domain.")
	test.AssertEquals(t, set[0].Hdr.Ttl, uint32(10))
	test.AssertEquals(t, set[0].Flag, uint8(0))
	test.AssertEquals(t, set[0].Tag, "issue")
	test.AssertEquals(t, set[0].Value, "ca.com")
}

func TestLookupCAA(t *testing.T) {
	testSrv := httptest.NewServer(http.HandlerFunc(mocks.GPDNSHandler))
	defer testSrv.Close()

	cpr := CAADistributedResolver{
		logger: log,
		Clients: map[string]*http.Client{
			"1.1.1.1": new(http.Client),
			"2.2.2.2": new(http.Client),
			"3.3.3.3": new(http.Client),
		},
		stats:       metrics.NewNoopScope(),
		maxFailures: 1,
		timeout:     time.Second,
		URI:         testSrv.URL,
	}

	set, err := cpr.LookupCAA(context.Background(), "test-domain")
	test.AssertNotError(t, err, "LookupCAA method failed")
	test.AssertEquals(t, len(set), 1)
	test.AssertEquals(t, set[0].Hdr.Name, "test-domain.")
	test.AssertEquals(t, set[0].Hdr.Ttl, uint32(10))
	test.AssertEquals(t, set[0].Flag, uint8(0))
	test.AssertEquals(t, set[0].Tag, "issue")
	test.AssertEquals(t, set[0].Value, "ca.com")

	set, err = cpr.LookupCAA(context.Background(), "break")
	test.AssertError(t, err, "LookupCAA should've failed")
	test.Assert(t, set == nil, "LookupCAA returned non-nil CAA set")

	set, err = cpr.LookupCAA(context.Background(), "break-rcode")
	test.AssertError(t, err, "LookupCAA should've failed")
	test.Assert(t, set == nil, "LookupCAA returned non-nil CAA set")

	set, err = cpr.LookupCAA(context.Background(), "break-dns-quorum")
	test.AssertError(t, err, "LookupCAA should've failed")
	test.Assert(t, set == nil, "LookupCAA returned non-nil CAA set")
}

type slightlyBrokenHandler struct {
	broken bool
	mu     sync.Mutex
}

func (sbh *slightlyBrokenHandler) Handler(w http.ResponseWriter, r *http.Request) {
	sbh.mu.Lock()
	defer sbh.mu.Unlock()
	if sbh.broken {
		w.WriteHeader(400)
		return
	}
	sbh.broken = true
	mocks.GPDNSHandler(w, r)
}

func TestHTTPQuorum(t *testing.T) {
	sbh := &slightlyBrokenHandler{}
	testSrv := httptest.NewServer(http.HandlerFunc(sbh.Handler))
	defer testSrv.Close()

	cpr := CAADistributedResolver{
		logger: log,
		Clients: map[string]*http.Client{
			"1.1.1.1": new(http.Client),
			"2.2.2.2": new(http.Client),
			"3.3.3.3": new(http.Client),
		},
		stats:       metrics.NewNoopScope(),
		maxFailures: 1,
		timeout:     time.Second,
		URI:         testSrv.URL,
	}

	set, err := cpr.LookupCAA(context.Background(), "test-domain")
	test.AssertError(t, err, "LookupCAA should've failed")
	test.Assert(t, set == nil, "LookupCAA returned non-nil CAA set")
}

func TestMarshalCanonicalCAASet(t *testing.T) {
	a, b := new(dns.CAA), new(dns.CAA)
	a.Value, b.Value = "a", "b"
	setA := []*dns.CAA{a, b}
	setB := []*dns.CAA{b, a}
	canonA, err := marshalCanonicalCAASet(setA)
	test.AssertNotError(t, err, "marshalCanonicalCAASet failed")
	canonB, err := marshalCanonicalCAASet(setB)
	test.AssertNotError(t, err, "marshalCanonicalCAASet failed")
	test.Assert(t, bytes.Equal(canonA, canonB), "sets do not match")
	cRR := dns.Copy(b)
	c := cRR.(*dns.CAA)
	c.Value = "c"
	c.Hdr.Ttl = 100
	hashC, err := marshalCanonicalCAASet([]*dns.CAA{c, a})
	test.AssertNotError(t, err, "marshalCanonicalCAASet failed")
	test.AssertEquals(t, c.Hdr.Ttl, uint32(100))
	test.Assert(t, bytes.Equal(canonA, canonB), fmt.Sprintf("Mismatching sets had same bytes: %x == %x", hashC, canonB))
}
