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

// We have had multiple issues resolving CAA records when the queries
// cross certain network paths. We have been unable to find a network
// solution to this so we are required to implement a multi-path
// resolution technique. This is a real hack and to be honest probably
// not the best solution to this problem. Ideally we would control our
// own distributed multi-path resolver but there are no publicly available
// ones.
//
// This implementation will talks to the Google Public DNS resolver over
// multiple paths using VPN interfaces (or any other method implementing
// hardware interfaces) with geographically distributed endpoints. In case
// the Google resolver encounters the same issues we do multiple queries
// for the same name in parallel and we require a M of N quorum of responses
// to return the SUCCESS return code. In order to prevent the case where a
// attacker may be able to exploit the Google resolver in some way we also
// require that the records returned from all requests are the same (as far
// as I can tell the Google DNS implementation doesn't share cache state
// between the distributed nodes so this should be safe).
//
// Since DNS isn't a super secure protocol and Google has recently introduced
// a public HTTPS API for their DNS resolver so instead we use that.

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
	Status           int        `json:"Status"`
	TC               bool       `json:"TC"`
	RD               bool       `json:"RD"`
	RA               bool       `json:"RA"`
	AD               bool       `json:"AD"`
	CD               bool       `json:"CD"`
	Question         []question `json:"Question"`
	Answer           []answer   `json:"Answer"`
	Additional       []answer   `json:"Additional"`
	EDNSClientSubnet string     `json:"edns_client_subnet"`
	Comment          string     `json:"Comment"`
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

func createClient(timeout, keepAlive time.Duration, itfAddr net.Addr) *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: keepAlive,
			LocalAddr: itfAddr,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return &http.Client{
		Transport: transport,
	}
}

type CAAPublicResolver struct {
	interfaceClients map[string]*http.Client
	stats            metrics.Scope
	maxFailures      int
}

func NewCAAPublicResolver(scope metrics.Scope, timeout, keepAlive time.Duration, maxFailures int, interfaces map[string]struct{}) (*CAAPublicResolver, error) {
	cpr := &CAAPublicResolver{stats: scope, maxFailures: maxFailures}
	allInterfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, itf := range allInterfaces {
		if _, ok := interfaces[itf.Name]; !ok {
			continue
		}
		// perhaps should just use the first address? not really sure here...
		allITFAddrs, err := itf.Addrs()
		if err != nil {
			return nil, err
		}
		for _, itfAddr := range allITFAddrs {
			cpr.interfaceClients[itfAddr.String()] = createClient(timeout, keepAlive, itfAddr) // fix
		}
	}
	return cpr, nil
}

func (cpr *CAAPublicResolver) queryCAA(ctx context.Context, req *http.Request, ic *http.Client) ([]*dns.CAA, error) {
	apiResp, err := ctxhttp.Do(ctx, ic, req)
	if err != nil {
		return nil, err
	}
	defer apiResp.Body.Close()
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

func hashCAASet(set []*dns.CAA) [32]byte {
	tbh := []byte{}
	sortedSet := caaSet(set)
	sort.Sort(sortedSet)
	for _, rr := range sortedSet {
		ttl := rr.Hdr.Ttl
		rr.Hdr.Ttl = 0                            // only variable that should jitter
		dns.PackRR(rr, tbh, len(tbh), nil, false) // don't compress RR
		rr.Hdr.Ttl = ttl
	}
	return sha256.Sum256(tbh)
}

func (cpr *CAAPublicResolver) LookupCAA(ctx context.Context, domain string) ([]*dns.CAA, error) {
	req, err := http.NewRequest("GET", apiURI, nil)
	if err != nil {
		return nil, err
	}
	query := make(url.Values)
	query.Add("name", domain)
	query.Add("type", "257") // CAA
	req.URL.RawQuery = query.Encode()

	results := make(chan queryResult, len(cpr.interfaceClients))
	for addr, interfaceClient := range cpr.interfaceClients {
		go func(ic *http.Client, ia string) {
			started := time.Now()
			records, err := cpr.queryCAA(ctx, req, ic)
			cpr.stats.TimingDuration(fmt.Sprintf("GPDNS.CAA.Latency.%s", ia), time.Since(started))
			results <- queryResult{records, err}
		}(interfaceClient, addr)
	}
	// collect everything
	failed := 0
	var CAAs []*dns.CAA
	var setHash [32]byte
	for r := range results {
		if err != nil {
			failed++
			if failed > cpr.maxFailures {
				return nil, fmt.Errorf("%d out of %d CAA queries failed", len(cpr.interfaceClients), failed)
			}
		}
		if CAAs != nil {
			CAAs = r.records
			setHash = hashCAASet(CAAs)
		} else {
			if len(r.records) != len(CAAs) || hashCAASet(r.records) != setHash {
				return nil, errors.New("mismatching CAA sets were returned")
			}
		}
	}
	return CAAs, nil
}
