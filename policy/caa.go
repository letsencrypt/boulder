// package va
package main

import (
//	"errors"
	"fmt"
	"strings"
	"github.com/miekg/dns"
	"github.com/miekg/unbound"
)

// CAA type

// CAA Holds decoded CAA record.
type CAA struct {
	flag uint8
	tag string
	value string
	valueBuf []byte
}

func newCAA(encodedRDATA []byte) *CAA {
	// RFC 6844 based record decoder
	if len(encodedRDATA) < 2 {
		// *very* badly formatted record, discard
		return nil
	}
	// first octet is uint8 flags
	flag := uint8(encodedRDATA[0])
	// second octet is uint8 length of tag
	tagLen := uint8(encodedRDATA[1])
	if uint8(len(encodedRDATA)) < 2+tagLen {
		// stupidly formatted record, discard
		return nil
	}

	// property tag
	tag := string(encodedRDATA[2:2+tagLen])

	// only decode tags we understand, value/valuebuf can be empty
	// (that would be stupid though...)
	value := ""
	var valueBuf []byte
	if tag == "issue" || tag == "issuewild" || tag == "iodef" {
		value = string(encodedRDATA[2+tagLen:])
	} else {
		valueBuf = encodedRDATA[2+tagLen:]
	}
	
	return &CAA{flag: flag, tag: tag, valueBuf: valueBuf, value: value}
}

// CAASet Contains returned CAA records filtered by tag.
type CAASet struct {
	issue []*CAA
	issuewild []*CAA
	iodef []*CAA
	unknown []*CAA
}

// CriticalUnknown Returns true if any CAA records have unknown tag properties and are flagged critical.
func (caaSet CAASet) criticalUnknown() bool {
	for _, caaRecord := range caaSet.unknown {
		// Critical flag is 1, but acording to RFC 6844
		// any flag other than 0 should currently be interpreted
		// as critical. 
		if caaRecord.flag > 0 {
			return true
		}
	}
	return false
}

func newCAASet(CAAs []*CAA) *CAASet {
	var issueSet []*CAA
	var issuewildSet []*CAA
	var iodefSet []*CAA
	var unknownSet []*CAA

	// idk if there is a better method for doing this...
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

// DNS utility methods

// DNSKEY records for "." so we don't have to request it every
// time.
const rootDNSKey = `			75417	IN	DNSKEY	257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq QxA+Uk1ihz0=`

func getNs(pubU *unbound.Unbound, domain string) (string, error) {
	// RFC 6844 states we should query the authoritative dns server
	// for a domain directly to avoid caching etc, so lets find its
	// IP address.
	// get NS records for domain
	r, err := pubU.Resolve(dns.Fqdn(domain), dns.TypeNS, dns.ClassINET)
	if err != nil {
		return "", fmt.Errorf("Resolving '%s' failed: %s", domain, err)
	}

	nsName := ""
	if r.HaveData {
		for _, record := range r.Rr {
			if record.Header().Rrtype == dns.TypeNS {
				// just grab the first NS domain
				nsName = record.(*dns.NS).Ns
				break
			}
		}
	} else {
		// if no NS records are returned its probably because domain is a CNAME
		// grab the authoritative NS server from the SOA record in the 
		// authority section of the answer.
		if len(r.AnswerPacket.Ns) > 0 {
			for _, record := range r.AnswerPacket.Ns {
				if record.Header().Rrtype == dns.TypeSOA {
					nsName = record.(*dns.SOA).Ns
					break
				}
			}
			// silly ns domain in SOA...
			if nsName == "." {
				for _, record := range r.AnswerPacket.Ns {
					if record.Header().Rrtype == dns.TypeSOA {
						r, err := pubU.Resolve(record.(*dns.SOA).Hdr.Name, dns.TypeNS, dns.ClassINET)
						if err != nil {
							return "", fmt.Errorf("Resolving '%s' failed: %s", record.(*dns.SOA).Hdr.Name, err)
						}
						if r.HaveData {
							for _, nsRecord := range r.Rr {
								if nsRecord.Header().Rrtype == dns.TypeNS {
									// just grab the first NS domain
									nsName = nsRecord.(*dns.NS).Ns
									break
								}
							}
						}
					}
				}
			}
		}
	}

	nsIPs, err := pubU.LookupIP(nsName)
	if err != nil {
		return "", fmt.Errorf("Resolving '%s' failed: %s", nsName, err)
	}
	if len(nsIPs) > 0 {
		// return first IP for NS
		return nsIPs[0].String(), nil
	}

	return "", fmt.Errorf("Address lookup did not return any IPs for %s", nsName)
}

func getDNSKeys(authU *unbound.Unbound, pubU *unbound.Unbound, domain string) (bool, error) {
	// get root via SOA based trickery
	r, err := pubU.Resolve(dns.Fqdn(domain), dns.TypeSOA, dns.ClassINET)
	if err != nil {
		return false, fmt.Errorf("Resolving '%s' failed: %s", domain, err)
	}

	rootDomain := ""
	if r.HaveData {
		// Get root domain from SOA answer
		for _, record := range r.Rr {
			if record.Header().Rrtype == dns.TypeSOA {
				rootDomain = record.(*dns.SOA).Hdr.Name
				break
			}
		}
	} else {
		if len(r.AnswerPacket.Ns) == 0 {
			return false, fmt.Errorf("Couldn't find the SOA record for '%s'", domain)
		}
		// Get root domain from SOA in authority response... (so silly)
		// iterate through authority because sometimes NSEC or RRSIG records
		// might be in there
		for _, record := range r.AnswerPacket.Ns {
			if record.Header().Rrtype == dns.TypeSOA {
				rootDomain = record.(*dns.SOA).Hdr.Name
				break
			}
		}
	}

	rootDomain = strings.TrimRight(rootDomain, ".")	
	splitDomain := strings.Split(rootDomain, ".")
	// build Trust Anchor list
	var taKeys []string
	for i := range splitDomain {
		taDomain := strings.Join(splitDomain[i:], ".")
		r, err := pubU.Resolve(dns.Fqdn(taDomain), dns.TypeDNSKEY, dns.ClassINET)
		if err != nil {
			return false, fmt.Errorf("Resolving '%s' failed: %s", taDomain, err)
		}

		if r.HaveData {
			for _, ta := range r.AnswerPacket.Answer {
				if ta.Header().Rrtype == dns.TypeDNSKEY {
					taKeys = append(taKeys, ta.String())
				}
			}
		} else {
			// cannot complete chain of trust, abort without error
			return false, nil
		}
	}
	// preload root key since every trust chain requires it
	taKeys = append(taKeys, rootDNSKey)
	for _, key := range taKeys {
		if err := authU.AddTa(key); err != nil {
			// only build *Chain of trust* if we have keys to make a full chain
			// from the root domain to . (ie [google.com. -> com. -> .])
			return false, fmt.Errorf("Couldn't add Trust Anchor: %s", err)
		}
	}

	// queries should now be authenticated against the chain of trust
	// by unbound.
	return true, nil
}

func getCaa(u *unbound.Unbound, domain string, alias bool) ([]*CAA, error) {
	// if looking for alias, get the canonical name and set
	// domain for it, can't really do this before authNs lookup
	// since Fwd isn't set yet...
	var CAAs []*CAA
	if alias {
		canonName, err := u.LookupCNAME(dns.Fqdn(domain))
		if err != nil {
			return CAAs, fmt.Errorf("CNAME lookup for '%s' failed: %s", domain, err)
		}
		// we already checked domain if alias is true, so don't
		// bother doing it again... (also this is weird)
		if canonName == "" || canonName == domain {
			return CAAs, nil
		}
		domain = canonName
	}

	// finally query for the CAA records
	r, err := u.Resolve(dns.Fqdn(domain), dns.TypeCAA, dns.ClassINET)
	if err != nil {
		return CAAs, fmt.Errorf("Resolving '%s' failed: %s", domain, err)
	}

	// check if response is bogus
	if !r.Bogus {
		if r.HaveData {
			for _, caaRecord := range r.Data {
				// Parse RDATA into CAA struct, r.Secure indicates
				// whether the CAA record was retrieved was using
				// DNSSEC for logging purposes. 
				CAAs = append(CAAs, newCAA(caaRecord))
			}
		}
	} else {
		// the DNSSEC validation has failed for some reason,
		// r.WhyBogus should tell us why.
		// this should probably be logged since it indicates an attack
		// of some sort (probably)
		return []*CAA{}, fmt.Errorf("CAA record response for '%s' appears bogus: %s", domain, r.WhyBogus)
	}

	return CAAs, nil
}

func getCaaSet(domain string) (*CAASet, bool, error) {
	// public resolver to get auth NS and DNSKEYs
	pubU := unbound.New()
	defer pubU.Destroy()
	// should probably be set from /etc/resolv.conf
	if err := pubU.SetFwd("8.8.8.8"); err != nil {
		return nil, false, fmt.Errorf("Setting forward resolver '%s' failed: %s", "8.8.8.8", err)
	}
	
	authNs, err := getNs(pubU, domain)
	if err != nil {
		return nil, false, err
	}

	authU := unbound.New()
	defer authU.Destroy()
	if err := authU.SetFwd(authNs); err != nil {
		return nil, false, fmt.Errorf("Setting forward resolver '%s' failed: %s", authNs, err)
	}

	// dnssec indicates if queries were made with an
	// initiated chain of trust, any bogus replies
	// will raise errors if this is true.
	dnssec, err := getDNSKeys(authU, pubU, domain)
	if err != nil {
		return nil, false, err
	}

	// remove trailing "." before splitting so we dont get a "" element
	domain = strings.TrimRight(domain, ".")	
	splitDomain := strings.Split(domain, ".")
	// RFC 6844 CAA set query sequence, 'x.y.z.com' => ['x.y.z.com', 'y.z.com', 'z.com']
	// dont query the tld...?
	for i := range splitDomain[0:len(splitDomain)-1] {
			queryDomain := strings.Join(splitDomain[i:], ".")

			for _, alias := range []bool{false, true} {
				// Look for CAA records in zone domain
				CAAs, err := getCaa(authU, queryDomain, alias); 
				if err != nil {
					return nil, dnssec, err
				}
				if len(CAAs) > 0 {
					return newCAASet(CAAs), dnssec, nil
				}

				// NSEC/3 check should be here
			}
	}
	
	return nil, dnssec, nil
}

// examples
func main() {
	testDomains := []string{"derrr.asd22", "google.com", "mail.google.com", "bracewel.net", "theguardian.co.uk", "pir.org", "mail1.pir.org", "comodo.com", "dnsseczombo.com", "antonyms.eu", "dmarcian.de", "instantssl.info", "www.zx.com", "www.dotsport.info", "tropicalnorthair.com", "sylkeschulze.de", "sylkeschulze.de", "somaf.de", "signing-milter.org", "nails.eu.org", "riverwillow.com.au", "mail2.bevenhall.se", "madtech.nl", "roe.ch"}

	for _, td := range testDomains {
		fmt.Printf("[%s]\n", td)
		caas, dnssec, err := getCaaSet(td)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("\tDNSSEC? %v\n\tCAA record set: %s\n", dnssec, caas)
	}
}

