package va

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/cactus/go-statsd-client/statsd"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
	"golang.org/x/net/context/ctxhttp"
)

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

func parseAnswer(as []answer) ([]dns.RR, error) {
	dnsAs := []dns.RR{}
	for _, a := range as {
		rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", a.Name, a.TTL, dns.TypeToString[a.Type], a.Data))
		if err != nil {
			return nil, err
		}
		dnsAs = append(dnsAs, rr)
	}
	return dnsAs, nil
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

type caaPublicResolver struct {
	interfaceClients map[string]*http.Client
	stats            statsd.Statter
	maxFailures      int
}

func newCAAPublicResolver(stats statsd.Statter, timeout, keepAlive time.Duration, maxFailures int, interfaces map[string]struct{}) (*caaPublicResolver, error) {
	cpr := &caaPublicResolver{stats: stats, maxFailures: maxFailures}
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

func (cpr *caaPublicResolver) queryCAA(ctx context.Context, req *http.Request, ic *http.Client) ([]dns.RR, error) {
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
	records []dns.RR
	err     error
}

func (cpr *caaPublicResolver) LookupCAA(ctx context.Context, domain string) ([]*dns.CAA, error) {
	req, err := http.NewRequest("GET", apiURI, nil)
	if err != nil {
		return nil, err
	}
	query := make(url.Values)
	query.Add("name", domain)
	query.Add("type", "257")
	req.URL.RawQuery = query.Encode()

	results := make(chan queryResult, len(cpr.interfaceClients))
	for addr, interfaceClient := range cpr.interfaceClients {
		go func(ic *http.Client, ia string) {
			started := time.Now()
			records, err := cpr.queryCAA(ctx, req, ic)
			cpr.stats.TimingDuration(fmt.Sprintf("GPDNS.CAA.Latency.%s", ia), time.Since(started), 1.0)
			results <- queryResult{records, err}
		}(interfaceClient, addr)
	}
	// collect everything
	failed := 0
	CAAs := []*dns.CAA{}
	for r := range results {
		if err != nil {
			failed++
			if failed > cpr.maxFailures {
				return nil, fmt.Errorf("%d out of %d CAA queries failed", len(cpr.interfaceClients), failed)
			}
		}
		for _, rr := range r.records {
			if rr.Header().Rrtype == dns.TypeCAA {
				if caaR, ok := rr.(*dns.CAA); ok {
					CAAs = append(CAAs, caaR)
				}
			}
		}
	}
	return CAAs, nil
}
