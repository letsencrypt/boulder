package policy

import (
	"fmt"
	"strings"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/unbound"
)

// CAA types

// CAA Holds decoded CAA record.
type CAA struct {
	flag uint8
	tag string
	value string
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
		// stupidly formatted record, discard
		return nil
	}
	tag := string(encodedRDATA[2:2+tagLen])
	// only decode tags we understand, value/valuebuf can be empty
	// (that would be stupid though...)
	var valueBuf []byte
	var value string
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
func (caaSet CAASet) CriticalUnknown() bool {
	if len(caaSet.unknown) > 0 {
		for _, caaRecord := range caaSet.unknown {
			// Critical flag is 1, but acording to RFC 6844any flag other than
			// 0 should currently be interpreted as critical. 
			if caaRecord.flag > 0 {
				return true
			}
		}
	}
	return false
}

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

// DNS utility methods

// DNSKEY record for "." so we don't have to query it every time we want to
// build a chain of trust.
const rootDNSKey = `			75417	IN	DNSKEY	257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq QxA+Uk1ihz0=`

func getNsAndRoot(pubU *unbound.Unbound, domain string) (string, string, error) {
	// get NS records for domain
	r, err := pubU.Resolve(dns.Fqdn(domain), dns.TypeNS, dns.ClassINET)
	if err != nil {
		return "", "", fmt.Errorf("Resolving '%s' failed: %s", domain, err)
	}

	nsName := ""
	rootDomain := ""
	if r.HaveData {
		for _, record := range r.Rr {
			if record.Header().Rrtype == dns.TypeNS {
				// just grab the first NS domain (this breaks things when the first
				// ns server returned is broken... ie offline/non-responsive on :53)
				nsName = record.(*dns.NS).Ns
				rootDomain = record.(*dns.NS).Hdr.Name
				break
			}
		}
	} else {
		// if no NS records are returned its probably because domain is a CNAME,
		// grab the authoritative NS server from the SOA record in the
		// authority section of the answer.
		if len(r.AnswerPacket.Ns) > 0 {
			for _, record := range r.AnswerPacket.Ns {
				if record.Header().Rrtype == dns.TypeSOA {
					nsName = record.(*dns.SOA).Ns
					rootDomain = record.(*dns.SOA).Hdr.Name
					break
				}
			}
			// silly ns in SOA...
			if nsName == "." {
				for _, record := range r.AnswerPacket.Ns {
					if record.Header().Rrtype == dns.TypeSOA {
						r, err := pubU.Resolve(record.(*dns.SOA).Hdr.Name, dns.TypeNS, dns.ClassINET)
						if err != nil {
							return "", "", fmt.Errorf("Resolving '%s' failed: %s", record.(*dns.SOA).Hdr.Name, err)
						}
						if r.HaveData {
							for _, nsRecord := range r.Rr {
								if nsRecord.Header().Rrtype == dns.TypeNS {
									// just grab the first NS domain
									nsName = nsRecord.(*dns.NS).Ns
									rootDomain = nsRecord.(*dns.NS).Hdr.Name
									break
								}
							}
						}
					}
				}
			}
		}
	}
	if nsName == "" || rootDomain == "" {
		return "", "", fmt.Errorf("Couldn't retrieve authoritative nameserver or zone root for '%s'", domain)
	}
	rootDomain = strings.TrimRight(rootDomain, ".")

	nsIPs, err := pubU.LookupIP(nsName)
	if err != nil {
		return "", "", fmt.Errorf("Resolving '%s' failed: %s", nsName, err)
	}
	if len(nsIPs) > 0 {
		// return first IP for NS
		return nsIPs[0].String(), rootDomain, nil
	}
	return "", "", fmt.Errorf("Address lookup did not return any IPs for '%s'", nsName)
}

func getDNSKeys(pubU *unbound.Unbound, authU *unbound.Unbound, domain string, rootDomain string) (bool, error) {
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

	return true, nil
}

func getCaa(u *unbound.Unbound, domain string, alias bool) ([]*CAA, error) {
	var CAAs []*CAA
	if alias {
		canonName, err := u.LookupCNAME(dns.Fqdn(domain))
		if err != nil {
			return CAAs, fmt.Errorf("CNAME lookup for '%s' failed: %s", domain, err)
		}
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
				CAAs = append(CAAs, newCAA(caaRecord))
			}
		}
	} else {
		return []*CAA{}, fmt.Errorf("CAA record response for '%s' appears bogus: %s", domain, r.WhyBogus)
	}

	return CAAs, nil
}

func getCaaSet(domain string) (*CAASet, bool, error) {
	pubU := unbound.New()
	defer pubU.Destroy()
	// should this be specifiable via a config var? (so that the list
	// of resolvers can be manually set... although that should just
	// be done in /etc/resolv.conf really)
	if err := pubU.ResolvConf("/etc/resolv.conf"); err != nil {
		return nil, false, err
	}

	authNs, rootDomain, err := getNsAndRoot(pubU, domain)
	if err != nil {
		return nil, false, err
	}

	authU := unbound.New()
	defer authU.Destroy()
	if err := authU.SetFwd(authNs); err != nil {
		return nil, false, fmt.Errorf("Setting forward resolver '%s' failed: %s", authNs, err)
	}

	dnssec, err := getDNSKeys(pubU, authU, domain, rootDomain)
	if err != nil {
		return nil, false, err
	}

	domain = strings.TrimRight(domain, ".")	
	splitDomain := strings.Split(domain, ".")
	// RFC 6844 CAA set query sequence, 'x.y.z.com' => ['x.y.z.com', 'y.z.com', 'z.com']
	for i := range splitDomain[0:len(splitDomain)-1] {
			queryDomain := strings.Join(splitDomain[i:], ".")
			for _, alias := range []bool{false, true} {
				CAAs, err := getCaa(authU, queryDomain, alias); 
				if err != nil {
					return nil, dnssec, err
				}
				if len(CAAs) > 0 {
					return newCAASet(CAAs), dnssec, nil
				}
			}
	}
	
	// no CAA records found, good times
	return nil, dnssec, nil
}
