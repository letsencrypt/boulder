package cdr

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/context"
	"golang.org/x/net/context/ctxhttp"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
)

// We have found a number of network operators which block or drop CAA
// queries that pass through their network which leads to consistent
// timeout failures from certain network perspectives. We have been
// unable to find a network solution to this so we are required to
// implement a multi-path resolution technique. This is a real hack and
// to be honest probably not the best solution to this problem. Ideally
// we would control our own distributed multi-path resolver but there
// are no publicly available ones.
//
// This implementation talks to the Google Public DNS resolver over
// multiple paths using HTTP proxies with geographically distributed
// endpoints. In case the Google resolver encounters the same issues we do
// multiple queries for the same name in parallel and we require a M of N
// quorum of responses to return the SUCCESS return code. In order to prevent
// the case where an attacker may be able to exploit the Google resolver in
// some way we also require that the records returned from all requests are
// the same (as far as I can tell the Google DNS implementation doesn't share
// cache state between the distributed nodes so this should be safe).
//
// Since DNS isn't a super secure protocol and Google has recently introduced
// a public HTTPS API for their DNS resolver we use that instead.
//
// API reference:
//   https://developers.google.com/speed/public-dns/docs/dns-over-https#api_specification

var apiURI = "https://dns.google.com/resolve"

func parseAnswer(as []core.GPDNSAnswer) ([]*dns.CAA, error) {
	rrs := []*dns.CAA{}
	// only bother parsing out CAA records
	for _, a := range as {
		if a.Type != dns.TypeCAA {
			continue
		}
		rr, err := dns.NewRR(fmt.Sprintf("%s %d IN CAA %s", a.Name, a.TTL, a.Data))
		if err != nil {
			return nil, err
		}
		if caaRR, ok := rr.(*dns.CAA); ok {
			rrs = append(rrs, caaRR)
		}
	}
	return rrs, nil
}

func createClient(proxy string) (*http.Client, string, error) {
	u, err := url.Parse(proxy)
	if err != nil {
		return nil, "", err
	}
	transport := &http.Transport{
		Proxy:               http.ProxyURL(u),
		TLSHandshakeTimeout: 10 * time.Second, // Same as http.DefaultTransport, doesn't override context
	}
	return &http.Client{
		Transport: transport,
	}, u.Host, nil
}

// CAADistributedResolver holds state needed to talk to GPDNS
type CAADistributedResolver struct {
	URI         string
	Clients     map[string]*http.Client
	stats       metrics.Scope
	maxFailures int
	timeout     time.Duration
	logger      blog.Logger
}

// New returns an initialized CAADistributedResolver which requires a M of N
// quorum to succeed where N = len(proxies) and M = N - maxFailures
func New(scope metrics.Scope, timeout time.Duration, maxFailures int, proxies []string, logger blog.Logger) (*CAADistributedResolver, error) {
	cdr := &CAADistributedResolver{
		Clients:     make(map[string]*http.Client, len(proxies)),
		URI:         apiURI,
		stats:       scope,
		maxFailures: maxFailures,
		timeout:     timeout,
		logger:      logger,
	}
	for _, p := range proxies {
		c, h, err := createClient(p)
		if err != nil {
			return nil, err
		}
		cdr.Clients[h] = c
	}
	return cdr, nil
}

// queryCAA sends the query request to the GPD API. If the return code is
// dns.RcodeSuccess the 'Answer' section is parsed for CAA records, otherwise
// an error is returned. Unlike bdns.DNSResolver.LookupCAA it will not repeat
// failed queries if the context has not expired as we expect to be running
// multiple queries in parallel and only need a M of N quorum (we also expect
// GPD to have quite good availability)
func (cdr *CAADistributedResolver) queryCAA(ctx context.Context, url string, ic *http.Client) ([]*dns.CAA, error) {
	apiResp, err := ctxhttp.Get(ctx, ic, url)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = apiResp.Body.Close()
	}()
	body, err := ioutil.ReadAll(&io.LimitedReader{R: apiResp.Body, N: 1024})
	if err != nil {
		return nil, err
	}
	if apiResp.StatusCode != http.StatusOK {
		if string(body) != "" {
			return nil, fmt.Errorf("Unexpected HTTP status code %d, body: %s", apiResp.StatusCode, body)
		}
		return nil, fmt.Errorf("Unexpected HTTP status code %d", apiResp.StatusCode)
	}
	var respObj core.GPDNSResponse
	err = json.Unmarshal(body, &respObj)
	if err != nil {
		return nil, err
	}
	if respObj.Status != dns.RcodeSuccess {
		if respObj.Comment != "" {
			return nil, fmt.Errorf("Query failed with %s: %s", dns.RcodeToString[respObj.Status], respObj.Comment)
		}
		return nil, fmt.Errorf("Query failed with %s", dns.RcodeToString[respObj.Status])
	}

	return parseAnswer(respObj.Answer)
}

type queryResult struct {
	records []*dns.CAA
	err     error
}

type caaSet []*dns.CAA

func (cs caaSet) Len() int           { return len(cs) }
func (cs caaSet) Less(i, j int) bool { return cs[i].Value < cs[j].Value } // sort by value...?
func (cs caaSet) Swap(i, j int)      { cs[i], cs[j] = cs[j], cs[i] }

func marshalCanonicalCAASet(set []*dns.CAA) ([]byte, error) {
	var err error
	offset, size := 0, 0
	sortedSet := caaSet(set)
	sort.Sort(sortedSet)
	for _, rr := range sortedSet {
		size += dns.Len(rr)
	}
	tbh := make([]byte, size)
	for _, rr := range sortedSet {
		ttl := rr.Hdr.Ttl
		rr.Hdr.Ttl = 0 // only variable that should jitter
		offset, err = dns.PackRR(rr, tbh, offset, nil, false)
		if err != nil {
			return nil, err
		}
		rr.Hdr.Ttl = ttl
	}
	return tbh, nil
}

// LookupCAA performs a multipath CAA DNS lookup using GPDNS
func (cdr *CAADistributedResolver) LookupCAA(ctx context.Context, domain string) ([]*dns.CAA, error) {
	query := make(url.Values)
	query.Add("name", domain)
	query.Add("type", strconv.Itoa(int(dns.TypeCAA)))
	uri, err := url.Parse(cdr.URI)
	if err != nil {
		return nil, err
	}
	uri.RawQuery = query.Encode()
	uriStr := uri.String()

	// min of ctx deadline and time.Now().Add(cdr.timeout)
	caaCtx, cancel := context.WithTimeout(ctx, cdr.timeout)
	defer cancel()
	results := make(chan queryResult, len(cdr.Clients))
	for addr, interfaceClient := range cdr.Clients {
		go func(ic *http.Client, ia string) {
			started := time.Now()
			records, err := cdr.queryCAA(caaCtx, uriStr, ic)
			cdr.stats.TimingDuration(fmt.Sprintf("CDR.GPDNS.Latency.%s", ia), time.Since(started))
			if err != nil {
				cdr.stats.Inc(fmt.Sprintf("CDR.GPDNS.Failures.%s", ia), 1)
				cdr.logger.AuditErr(fmt.Sprintf("queryCAA failed [via %s]: %s", ia, err))
			}
			results <- queryResult{records, err}
		}(interfaceClient, addr)
	}
	// collect everything
	failed := 0
	var CAAs []*dns.CAA
	var canonicalSet []byte
	for i := 0; i < len(cdr.Clients); i++ {
		r := <-results
		if r.err != nil {
			failed++
			if failed > cdr.maxFailures {
				cdr.stats.Inc("CDR.QuorumFailed", 1)
				cdr.logger.AuditErr(fmt.Sprintf("%d out of %d CAA queries failed", len(cdr.Clients), failed))
				return nil, r.err
			}
		}
		if CAAs == nil {
			CAAs = r.records
			canonicalSet, err = marshalCanonicalCAASet(CAAs)
			if err != nil {
				return nil, err
			}
		} else {
			thisSet, err := marshalCanonicalCAASet(r.records)
			if err != nil {
				return nil, err
			}
			if len(r.records) != len(CAAs) || !bytes.Equal(thisSet, canonicalSet) {
				cdr.stats.Inc("CDR.MismatchedSet", 1)
				return nil, errors.New("mismatching CAA record sets were returned")
			}
		}
	}
	cdr.stats.Inc("CDR.Quorum", 1)
	return CAAs, nil
}
