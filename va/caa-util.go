// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package va

import (
	"encoding/hex"
	"errors"
	"strconv"
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

// RFC 6844 based CAA record decoder
func newCAA(encodedRDATA []byte) *CAA {
	if len(encodedRDATA) < 2 {
		// *very* badly formatted record, discard
		return nil
	}

	// first octet is uint8 flags
	flag := uint8(encodedRDATA[0])

	// second octet is uint8 length of tag
	tagLen := uint8(encodedRDATA[1])

	if uint8(len(encodedRDATA)) < 2+tagLen {
		// badly formatted record, discard
		return nil
	}
	tag := string(encodedRDATA[2 : 2+tagLen])

	// Only decode tags we understand, value/valuebuf can be empty
	// (that would be weird though...)
	var valueBuf []byte
	var value string
	if tag == "issue" || tag == "issuewild" || tag == "iodef" {
		value = string(encodedRDATA[2+tagLen:])
	} else {
		// unknown tag value may not be string, so store in buf
		valueBuf = encodedRDATA[2+tagLen:]
	}

	return &CAA{flag: flag, tag: tag, valueBuf: valueBuf, value: value}
}

// Filtered CAA records
type CAASet struct {
	issue     []*CAA
	issuewild []*CAA
	iodef     []*CAA
	unknown   []*CAA
}

// returns true if any CAA records have unknown tag properties and are flagged critical.
func (caaSet CAASet) criticalUnknown() bool {
	if len(caaSet.unknown) > 0 {
		for _, caaRecord := range caaSet.unknown {
			// Critical flag is 1, but according to RFC 6844 any flag other than
			// 0 should currently be interpreted as critical.
			if caaRecord.flag > 0 {
				return true
			}
		}
	}

	return false
}

// Filter CAA records by property
func newCAASet(CAAs []*CAA) *CAASet {
	var issueSet []*CAA
	var issuewildSet []*CAA
	var iodefSet []*CAA
	var unknownSet []*CAA

	for _, caaRecord := range CAAs {
		switch caaRecord.tag {
		case "issue":
			issueSet = append(issueSet, caaRecord)
		case "issuewild":
			issuewildSet = append(issuewildSet, caaRecord)
		case "iodef":
			iodefSet = append(iodefSet, caaRecord)
		default:
			unknownSet = append(unknownSet, caaRecord)
		}
	}

	return &CAASet{issue: issueSet, issuewild: issuewildSet, iodef: iodefSet, unknown: unknownSet}
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

func getCaa(dnsResolver *core.DNSResolver, domain string, alias bool) ([]*CAA, error) {
	if alias {
		// Check if there is a CNAME record for domain
		canonName, err := lookupCNAME(dnsResolver, dns.Fqdn(domain))
		if err != nil {
			return nil, err
		}
		if canonName == "" || canonName == domain {
			return []*CAA{}, nil
		}
		domain = canonName
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeCAA)

	r, _, err := dnsResolver.LookupDNSSEC(m)
	if err != nil {
		return nil, err
	}

	var CAAs []*CAA
	for _, answer := range r.Answer {
		if answer.Header().Rrtype == dns.TypeCAA {
			recordFields := strings.Fields(answer.String())
			if len(recordFields) < 7 {
				// Malformed record
				err = errors.New("DNS response contains badly formatted CAA record")
				return nil, err
			}

			caaLen, err := strconv.Atoi(recordFields[5])
			if err != nil {
				return nil, err
			}

			// Decode hex encoded RDATA field
			caaData, err := hex.DecodeString(strings.Join(recordFields[6:], ""))
			if err != nil {
				return nil, err
			}

			if caaLen != len(caaData) {
				// Malformed record
				err = errors.New("RDATA length field doesn't match RDATA length")
				return nil, err
			}
			CAAs = append(CAAs, newCAA([]byte(caaData)))
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
