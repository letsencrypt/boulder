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

// Name returns a name that uniquely identifies the monitor that
// configured this `Prober`. Used for metrics and logging
func (p DNSProbe) Name() string {
	return fmt.Sprintf("%s-%s-%s-%s", p.Proto, p.Server, p.QName, dns.TypeToString[p.QType])
}

// Kind returns a name that uniquely identifies the `Kind` of `Prober`.
// Used for metrics and logging
func (p DNSProbe) Kind() string {
	return "DNS"
}

// Probe attempts the configured DNS query
func (p DNSProbe) Probe(timeout time.Duration) (bool, time.Duration) {
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
