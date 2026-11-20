package va

import (
	"github.com/miekg/dns"
)

// supportedMandatoryKeys are the SvcParamKeys that may appear in an HTTPS
// record's "mandatory" list without making us ignore the record. We don't
// process all of these (e.g. we ignore the IP hints), but we recognize their
// names and we know they don't affect our behavior.
var supportedMandatoryKeys = map[dns.SVCBKey]bool{
	dns.SVCB_ALPN:            true,
	dns.SVCB_NO_DEFAULT_ALPN: true,
	dns.SVCB_PORT:            true,
	dns.SVCB_ECHCONFIG:       true,
	dns.SVCB_IPV4HINT:        true,
	dns.SVCB_IPV6HINT:        true,
}

// echConfigListFromHTTPS returns the ECHConfigList from the most preferred of
// the given HTTPS records that applies to a TLS connection to the records'
// owner on the given port, or nil if there is none.
func echConfigListFromHTTPS(rrs []*dns.HTTPS, port int) []byte {
	var echConfigList []byte
	var bestPriority uint16
	for _, rr := range rrs {
		// RFC 9460, Section 1.2: SvcPriority... A value of 0 indicates AliasMode.
		//
		// RFC 9460, Section 2.4.1: If an RRset contains a record in AliasMode,
		// the recipient MUST ignore any ServiceMode records in the set.
		//
		// An AliasMode record can't include ECH configuration, so ignore everything.
		if rr.Priority == 0 {
			return nil
		}

		// RFC 9460, Section 2.5.2: if TargetName has the value ".", then the owner
		// name of this record MUST be used as the effective TargetName.
		//
		// Since we're querying for ECH directly at the domain we're validating, we
		// only care about records whose target is the queried-for domain, whether
		// given as "." or spelled out.
		if rr.Target != "." && dns.CanonicalName(rr.Target) != dns.CanonicalName(rr.Hdr.Name) {
			continue
		}

		ech := echFromServiceRecord(rr, port)
		if len(ech) == 0 {
			continue
		}

		// RFC 9460, Section 3: Sort the records by ascending SvcPriority.
		if echConfigList == nil || rr.Priority < bestPriority {
			echConfigList = ech
			bestPriority = rr.Priority
		}
	}
	return echConfigList
}

// echFromServiceRecord returns the ech SvcParam of a ServiceMode HTTPS record,
// or nil if the record doesn't have one, applies to the wrong port, or has
// mandatory SvcParams that we don't recognize.
func echFromServiceRecord(rr *dns.HTTPS, port int) []byte {
	var ech []byte
	for _, kv := range rr.Value {
		switch v := kv.(type) {
		case *dns.SVCBPort:
			if int(v.Port) != port {
				return nil
			}
		case *dns.SVCBMandatory:
			for _, key := range v.Code {
				if !supportedMandatoryKeys[key] {
					return nil
				}
			}
		case *dns.SVCBECHConfig:
			ech = v.ECH
		}
	}
	return ech
}
