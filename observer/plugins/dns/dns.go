package main

import (
	"fmt"
	"time"

	odns "github.com/miekg/dns"
)

// Probe is the exported handler object for monitors configured to use
// DNS probes
type Probe struct {
	QProto   string
	QRecurse bool
	QName    string
	QServer  string
	QType    uint16
}

// Do performs the DNS query provided by the monitor settings
func (p Probe) Do(tick time.Time, timeout time.Duration) (bool, time.Duration) {
	m := new(odns.Msg)
	m.SetQuestion(odns.Fqdn(p.QName), p.QType)
	m.RecursionDesired = p.QRecurse
	c := odns.Client{Timeout: timeout}
	r, _, err := c.Exchange(m, p.QServer)
	if err != nil {
		return false, time.Since(tick)
	}
	if r == nil {
		fmt.Println("response was nil")
		return false, time.Since(tick)
	}
	if r.Rcode != odns.RcodeSuccess {
		fmt.Println("response code failed")
		return false, time.Since(tick)
	}
	return true, time.Since(tick)
}

func main() {
	return
}
