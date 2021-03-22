package probers

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// DNSProbe is the exported 'Prober' object for monitors configured to
// perform DNS requests.
type DNSProbe struct {
	Proto   string
	Server  string
	Recurse bool
	QName   string
	QType   uint16
}

// Name returns a string that uniquely identifies the monitor.
func (p DNSProbe) Name() string {
	recursion := func() string {
		if p.Recurse {
			return "recurse"
		}
		return "no-recurse"
	}()
	return fmt.Sprintf(
		"%s-%s-%s-%s-%s", p.Server, p.Proto, recursion, dns.TypeToString[p.QType], p.QName)
}

// Kind returns a name that uniquely identifies the `Kind` of `Prober`.
func (p DNSProbe) Kind() string {
	return "DNS"
}

// Probe performs the configured DNS query.
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
