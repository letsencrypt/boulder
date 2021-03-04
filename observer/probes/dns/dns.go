package observer

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// DNSProbe is the exported handler object for monitors configured to
// perform DNS queries
type DNSProbe struct {
	Proto   string
	Server  string
	Recurse bool
	QName   string
	QType   uint16
}

// Name returns a name that uniquely identifies the monitor
func (p DNSProbe) Name() string {
	return fmt.Sprintf("%s-%s-%s-%s", p.Proto, p.Server, p.QName, dns.TypeToString[p.QType])
}

// Type returns a name that uniquely identifies the monitor
func (p DNSProbe) Type() string {
	return "DNS"
}

// Do is the query handler for HTTP probes
func (p DNSProbe) Do(timeout time.Duration) (bool, time.Duration) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(p.QName), p.QType)
	m.RecursionDesired = p.Recurse
	start := time.Now()
	c := dns.Client{Timeout: timeout, Net: p.Proto}
	r, _, err := c.Exchange(m, p.Server)
	if err != nil {
		return false, time.Since(start)
	}
	if r == nil {
		return false, time.Since(start)
	}
	if r.Rcode != dns.RcodeSuccess {
		return false, time.Since(start)
	}
	return true, time.Since(start)
}
