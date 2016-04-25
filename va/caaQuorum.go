package va

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/context"
	"golang.org/x/net/context/ctxhttp"

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
// a public HTTPS API for their DNS resolver so instead we use that.
//
// API reference:
//   https://developers.google.com/speed/public-dns/docs/dns-over-https#api_specification

var apiURI = "https://dns.google.com/resolve"

type question struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
}

type answer struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

type response struct {
	// Ignored fields
	//   tc
	//   rd
	//   ra
	//   ad
	//   cd
	//   question
	//   additional
	//   edns_client_subnet
	Status  int      `json:"Status"`
	Answer  []answer `json:"Answer"`
	Comment string   `json:"Comment"`
}

func parseAnswer(as []answer) ([]*dns.CAA, error) {
	rrs := []*dns.CAA{}
	// only bother parsing out CAA records
	for _, a := range as {
		if a.Type != 257 {
			continue
		}
		rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", a.Name, a.TTL, dns.TypeToString[a.Type], a.Data))
		if err != nil {
			return nil, err
		}
		if caaRR, ok := rr.(*dns.CAA); ok {
			rrs = append(rrs, caaRR)
		}
	}
	return rrs, nil
}

func createClient(timeout, keepAlive time.Duration, proxy string) (*http.Client, string, error) {
	u, err := url.Parse(proxy)
	if err != nil {
		return nil, "", err
	}
	transport := &http.Transport{
		Proxy: http.ProxyURL(u),
		Dial: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: keepAlive,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}, u.Host, nil
}

// CAAPublicResolver holds state needed to talk to GPDNS
type CAAPublicResolver struct {
	clients     map[string]*http.Client
	stats       metrics.Scope
	maxFailures int
}

// NewCAAPublicResolver returns a initialized CAAPublicResolver
func NewCAAPublicResolver(scope metrics.Scope, timeout, keepAlive time.Duration, maxFailures int, proxies []string) (*CAAPublicResolver, error) {
	cpr := &CAAPublicResolver{stats: scope, maxFailures: maxFailures}
	for _, p := range proxies {
		c, h, err := createClient(timeout, keepAlive, p)
		if err != nil {
			return nil, err
		}
		cpr.clients[h] = c
	}
	return cpr, nil
}

func (cpr *CAAPublicResolver) queryCAA(ctx context.Context, req *http.Request, ic *http.Client) ([]*dns.CAA, error) {
	apiResp, err := ctxhttp.Do(ctx, ic, req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = apiResp.Body.Close()
	}()
	body, err := ioutil.ReadAll(apiResp.Body)
	if err != nil {
		return nil, err
	}
	var respObj response
	err = json.Unmarshal(body, &respObj)
	if err != nil {
		return nil, err
	}
	if respObj.Status != dns.RcodeSuccess {
		if respObj.Comment != "" {
			return nil, fmt.Errorf("Query failed with %s: %s", dns.RcodeToString[respObj.Status], respObj.Comment)
		}
		return nil, fmt.Errorf("Query failed wtih %s", dns.RcodeToString[respObj.Status])
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

func hashCAASet(set []*dns.CAA) ([32]byte, error) {
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
			return [32]byte{}, err
		}
		rr.Hdr.Ttl = ttl
	}
	return sha256.Sum256(tbh), nil
}

// LookupCAA performs a multipath CAA DNS lookup using GPDNS
func (cpr *CAAPublicResolver) LookupCAA(ctx context.Context, domain string) ([]*dns.CAA, error) {
	req, err := http.NewRequest("GET", apiURI, nil)
	if err != nil {
		return nil, err
	}
	query := make(url.Values)
	query.Add("name", domain)
	query.Add("type", "257") // CAA
	req.URL.RawQuery = query.Encode()

	results := make(chan queryResult, len(cpr.clients))
	for addr, interfaceClient := range cpr.clients {
		go func(ic *http.Client, ia string) {
			started := time.Now()
			records, err := cpr.queryCAA(ctx, req, ic)
			cpr.stats.TimingDuration(fmt.Sprintf("GPDNS.CAA.Latency.%s", ia), time.Since(started))
			results <- queryResult{records, err}
		}(interfaceClient, addr)
	}
	// collect everything
	i := 0
	failed := 0
	var CAAs []*dns.CAA
	var setHash [32]byte
	for r := range results {
		if err != nil {
			failed++
			if failed > cpr.maxFailures {
				return nil, fmt.Errorf("%d out of %d CAA queries failed", len(cpr.clients), failed)
			}
		}
		if CAAs == nil {
			CAAs = r.records
			setHash, err = hashCAASet(CAAs)
			if err != nil {
				return nil, err
			}
		} else {
			hashedSet, err := hashCAASet(r.records)
			if err != nil {
				return nil, err
			}
			if len(r.records) != len(CAAs) || hashedSet != setHash {
				return nil, errors.New("mismatching CAA record sets were returned")
			}
		}
		i++
		if i == len(cpr.clients) {
			close(results) // break loop
		}
	}
	return CAAs, nil
}
