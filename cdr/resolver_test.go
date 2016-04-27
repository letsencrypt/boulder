package cdr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/context"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
)

var log = blog.UseMock()

func testHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Query().Get("name") {
	case "test-domain":
		resp := response{
			Status: dns.RcodeSuccess,
			Answer: []answer{
				{"test-domain", 257, 10, "0 issue \"symantec.com\""},
			},
		}
		data, err := json.Marshal(resp)
		if err != nil {
			return
		}
		w.Write(data)
	}
}

func TestParseAnswer(t *testing.T) {
	as := []answer{
		{"a", 257, 10, "0 issue \"symantec.com\""},
		{"b", 1, 10, "1.1.1.1"},
	}

	r, err := parseAnswer(as)
	test.AssertNotError(t, err, "Failed to parse records")
	test.AssertEquals(t, len(r), 1)
	test.AssertEquals(t, r[0].Hdr.Name, "a.")
	test.AssertEquals(t, r[0].Hdr.Ttl, uint32(10))
	test.AssertEquals(t, r[0].Flag, uint8(0))
	test.AssertEquals(t, r[0].Tag, "issue")
	test.AssertEquals(t, r[0].Value, "symantec.com")
}

func TestQueryCAA(t *testing.T) {
	testServ := httptest.NewServer(http.HandlerFunc(testHandler))
	defer testServ.Close()

	req, err := http.NewRequest("GET", testServ.URL, nil)
	test.AssertNotError(t, err, "Failed to create request")
	query := make(url.Values)
	query.Add("name", "test-domain")
	query.Add("type", "257") // CAA
	req.URL.RawQuery = query.Encode()

	client := new(http.Client)
	cpr := CAADistributedResolver{logger: log}
	set, err := cpr.queryCAA(context.Background(), req, client)
	test.AssertNotError(t, err, "queryCAA failed")
	test.AssertEquals(t, len(set), 1)
	test.AssertEquals(t, set[0].Hdr.Name, "test-domain.")
	test.AssertEquals(t, set[0].Hdr.Ttl, uint32(10))
	test.AssertEquals(t, set[0].Flag, uint8(0))
	test.AssertEquals(t, set[0].Tag, "issue")
	test.AssertEquals(t, set[0].Value, "symantec.com")
}

func TestLookupCAA(t *testing.T) {
	testServ := httptest.NewServer(http.HandlerFunc(testHandler))
	defer testServ.Close()

	apiURI = testServ.URL
	cpr := CAADistributedResolver{
		logger: log,
		clients: map[string]*http.Client{
			"1.1.1.1": new(http.Client),
			"2.2.2.2": new(http.Client),
			"3.3.3.3": new(http.Client),
		},
		stats:       metrics.NewNoopScope(),
		maxFailures: 1,
		timeout:     time.Second,
	}

	set, err := cpr.LookupCAA(context.Background(), "test-domain")
	test.AssertNotError(t, err, "LookupCAA method failed")
	test.AssertEquals(t, len(set), 1)
	test.AssertEquals(t, set[0].Hdr.Name, "test-domain.")
	test.AssertEquals(t, set[0].Hdr.Ttl, uint32(10))
	test.AssertEquals(t, set[0].Flag, uint8(0))
	test.AssertEquals(t, set[0].Tag, "issue")
	test.AssertEquals(t, set[0].Value, "symantec.com")
}

func TestHashCAASet(t *testing.T) {
	a, b := new(dns.CAA), new(dns.CAA)
	a.Value, b.Value = "a", "b"
	setA := []*dns.CAA{a, b}
	setB := []*dns.CAA{b, a}
	hashA, err := hashCAASet(setA)
	test.AssertNotError(t, err, "hashCAASet failed")
	hashB, err := hashCAASet(setB)
	test.AssertNotError(t, err, "hashCAASet failed")
	test.AssertEquals(t, hashA, hashB)
	cRR := dns.Copy(b)
	c := cRR.(*dns.CAA)
	c.Value = "c"
	c.Hdr.Ttl = 100
	hashC, err := hashCAASet([]*dns.CAA{c, a})
	test.AssertNotError(t, err, "hashCAASet failed")
	test.AssertEquals(t, c.Hdr.Ttl, uint32(100))
	test.Assert(t, hashC != hashB, fmt.Sprintf("Mismatching sets had same hash: %x == %x", hashC, hashB))
}
