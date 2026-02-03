package probers

import (
	"context"
	"fmt"

	"github.com/miekg/dns"
)

// DNSProbe is the exported 'Prober' object for monitors configured to
// perform DNS requests.
type DNSProbe struct {
	proto   string
	server  string
	recurse bool
	qname   string
	qtype   uint16
}

// Name returns a string that uniquely identifies the monitor.
func (p DNSProbe) Name() string {
	recursion := func() string {
		if p.recurse {
			return "recurse"
		}
		return "no-recurse"
	}()
	return fmt.Sprintf(
		"%s-%s-%s-%s-%s", p.server, p.proto, recursion, dns.TypeToString[p.qtype], p.qname)
}

// Kind returns a name that uniquely identifies the `Kind` of `Prober`.
func (p DNSProbe) Kind() string {
	return "DNS"
}

// Probe performs the configured DNS query.
func (p DNSProbe) Probe(ctx context.Context) bool {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(p.qname), p.qtype)
	m.RecursionDesired = p.recurse
	c := dns.Client{Net: p.proto}

	r, _, err := c.ExchangeContext(ctx, m, p.server)
	if err != nil {
		return false
	}
	if r == nil {
		return false
	}
	if r.Rcode != dns.RcodeSuccess {
		return false
	}
	return true
}
