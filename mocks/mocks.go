// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mocks

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"
)

// MockDNS is a mock
type MockDNS struct {
}

// ExchangeOne is a mock
func (mock *MockDNS) ExchangeOne(hostname string, qt uint16) (rsp *dns.Msg, rtt time.Duration, err error) {
	return nil, 0, nil
}

// LookupTXT is a mock
func (mock *MockDNS) LookupTXT(hostname string) ([]string, time.Duration, error) {
	if hostname == "_acme-challenge.servfail.com" {
		return nil, 0, fmt.Errorf("SERVFAIL")
	}
	return []string{"hostname"}, 0, nil
}

// LookupHost is a mock
func (mock *MockDNS) LookupHost(hostname string) ([]net.IP, time.Duration, time.Duration, error) {
	return nil, 0, 0, nil
}

// LookupCNAME is a mock
func (mock *MockDNS) LookupCNAME(domain string) (string, time.Duration, error) {
	switch strings.TrimRight(domain, ".") {
	case "cname-absent.com":
		return "absent.com.", 30, nil
	case "cname-critical.com":
		return "critical.com.", 30, nil
	case "cname-present.com", "cname-and-dname.com":
		return "cname-target.present.com.", 30, nil
	case "cname2-present.com":
		return "cname-present.com.", 30, nil
	case "a.cname-loop.com":
		return "b.cname-loop.com.", 30, nil
	case "b.cname-loop.com":
		return "a.cname-loop.com.", 30, nil
	case "www.caa-loop.com":
		// nothing wrong with CNAME, but prevents CAA algorithm from terminating
		return "oops.www.caa-loop.com.", 30, nil
	case "cname2servfail.com":
		return "servfail.com.", 30, nil
	case "cname-servfail.com":
		return "", 0, fmt.Errorf("SERVFAIL")
	case "cname2dname.com":
		return "dname2cname.com.", 30, nil
	default:
		return "", 0, nil
	}
}

// LookupDNAME is a mock
func (mock *MockDNS) LookupDNAME(domain string) (string, time.Duration, error) {
	switch strings.TrimRight(domain, ".") {
	case "cname-and-dname.com", "dname-present.com":
		return "dname-target.present.com.", time.Minute, nil
	case "a.dname-loop.com":
		return "b.dname-loop.com.", time.Minute, nil
	case "b.dname-loop.com":
		return "a.dname-loop.com.", time.Minute, nil
	case "dname2cname.com":
		return "cname2-present.com.", time.Minute, nil
	case "dname-servfail.com":
		return "", time.Minute, fmt.Errorf("SERVFAIL")
	default:
		return "", 0, nil
	}
}

// LookupCAA is a mock
func (mock *MockDNS) LookupCAA(domain string) ([]*dns.CAA, time.Duration, error) {
	var results []*dns.CAA
	var record dns.CAA
	switch strings.TrimRight(domain, ".") {
	case "reserved.com":
		record.Tag = "issue"
		record.Value = "symantec.com"
		results = append(results, &record)
	case "critical.com":
		record.Flag = 1
		record.Tag = "issue"
		record.Value = "symantec.com"
		results = append(results, &record)
	case "present.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org"
		results = append(results, &record)
	case "servfail.com":
		return results, 0, fmt.Errorf("SERVFAIL")
	}
	return results, 0, nil
}

// LookupMX is a mock
func (mock *MockDNS) LookupMX(domain string) ([]string, time.Duration, error) {
	switch strings.TrimRight(domain, ".") {
	case "letsencrypt.org":
		fallthrough
	case "email.com":
		return []string{"mail.email.com"}, 0, nil
	}
	return nil, 0, nil
}
