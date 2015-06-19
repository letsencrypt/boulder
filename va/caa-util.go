// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package va

import (
	"errors"
	"strings"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/policy"
)

// CAA Holds decoded CAA record.
type CAA struct {
	flag     uint8
	tag      string
	value    string
	valueBuf []byte
}

// CAASet consists of filtered CAA records
type CAASet struct {
	Issue     []*dns.CAA
	Issuewild []*dns.CAA
	Iodef     []*dns.CAA
	Unknown   []*dns.CAA
}

// returns true if any CAA records have unknown tag properties and are flagged critical.
func (caaSet CAASet) criticalUnknown() bool {
	if len(caaSet.Unknown) > 0 {
		for _, caaRecord := range caaSet.Unknown {
			// Critical flag is 1, but according to RFC 6844 any flag other than
			// 0 should currently be interpreted as critical.
			if caaRecord.Flag > 0 {
				return true
			}
		}
	}

	return false
}

// Filter CAA records by property
func newCAASet(CAAs []*dns.CAA) *CAASet {
	var filtered CAASet

	for _, caaRecord := range CAAs {
		switch caaRecord.Tag {
		case "issue":
			filtered.Issue = append(filtered.Issue, caaRecord)
		case "issuewild":
			filtered.Issuewild = append(filtered.Issuewild, caaRecord)
		case "iodef":
			filtered.Iodef = append(filtered.Iodef, caaRecord)
		default:
			filtered.Unknown = append(filtered.Unknown, caaRecord)
		}
	}

	return &filtered
}

// Looks up CNAME records for domain and returns either the target or ""
func lookupCNAME(dnsResolver *core.DNSResolver, domain string) (string, error) {
	m := new(dns.Msg)
	m.SetQuestion(domain, dns.TypeCNAME)

	r, _, err := dnsResolver.LookupDNSSEC(m)
	if err != nil {
		return "", err
	}

	for _, answer := range r.Answer {
		if cname, ok := answer.(*dns.CNAME); ok {
			return cname.Target, nil
		}
	}

	return "", nil
}

func getCaa(dnsResolver *core.DNSResolver, domain string, alias bool) ([]*dns.CAA, error) {
	if alias {
		// Check if there is a CNAME record for domain
		canonName, err := lookupCNAME(dnsResolver, dns.Fqdn(domain))
		if err != nil {
			return nil, err
		}
		if canonName == "" || canonName == domain {
			return []*dns.CAA{}, nil
		}
		domain = canonName
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeCAA)

	r, _, err := dnsResolver.LookupDNSSEC(m)
	if err != nil {
		return nil, err
	}

	var CAAs []*dns.CAA
	for _, answer := range r.Answer {
		if answer.Header().Rrtype == dns.TypeCAA {
			caaR, ok := answer.(*dns.CAA)
			if !ok {
				err = errors.New("Badly formatted record")
				return nil, err
			}
			CAAs = append(CAAs, caaR)
		}
	}

	return CAAs, nil
}

func getCaaSet(domain string, dnsResolver *core.DNSResolver) (*CAASet, error) {
	domain = strings.TrimRight(domain, ".")
	splitDomain := strings.Split(domain, ".")
	// RFC 6844 CAA set query sequence, 'x.y.z.com' => ['x.y.z.com', 'y.z.com', 'z.com']
	for i := range splitDomain {
		queryDomain := strings.Join(splitDomain[i:], ".")
		// Don't query a public suffix
		if _, present := policy.PublicSuffixList[queryDomain]; present {
			break
		}

		// Query CAA records for domain and its alias if it has a CNAME
		for _, alias := range []bool{false, true} {
			CAAs, err := getCaa(dnsResolver, queryDomain, alias)
			if err != nil {
				return nil, err
			}

			if len(CAAs) > 0 {
				return newCAASet(CAAs), nil
			}
		}
	}

	// no CAA records found
	return nil, nil
}
