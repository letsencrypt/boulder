package challtestsrv

import (
	"github.com/miekg/dns"
)

// SetDefaultDNSIPv4 sets the default IPv4 address used for A query responses
// that don't match hosts added with AddDNSARecord. Use "" to disable default
// A query responses.
func (s *ChallSrv) SetDefaultDNSIPv4(addr string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	s.dnsMocks.defaultIPv4 = addr
}

// SetDefaultDNSIPv6 sets the default IPv6 address used for AAAA query responses
// that don't match hosts added with AddDNSAAAARecord. Use "" to disable default
// AAAA query responses.
func (s *ChallSrv) SetDefaultDNSIPv6(addr string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	s.dnsMocks.defaultIPv6 = addr
}

// GetDefaultDNSIPv4 gets the default IPv4 address used for A query responses
// (in string form), or an empty string if no default is being used.
func (s *ChallSrv) GetDefaultDNSIPv4() string {
	s.challMu.RLock()
	defer s.challMu.RUnlock()
	return s.dnsMocks.defaultIPv4
}

// GetDefaultDNSIPv6 gets the default IPv6 address used for AAAA query responses
// (in string form), or an empty string if no default is being used.
func (s *ChallSrv) GetDefaultDNSIPv6() string {
	s.challMu.RLock()
	defer s.challMu.RUnlock()
	return s.dnsMocks.defaultIPv6
}

// AddDNSCNAMERecord sets a CNAME record that will be used like an alias when
// querying for other DNS records for the given host.
func (s *ChallSrv) AddDNSCNAMERecord(host string, value string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	host = dns.Fqdn(host)
	value = dns.Fqdn(value)
	s.dnsMocks.cnameRecords[host] = value
}

// GetDNSCNAMERecord returns a target host if a CNAME is set for the querying
// host and an empty string otherwise.
func (s *ChallSrv) GetDNSCNAMERecord(host string) string {
	s.challMu.RLock()
	host = dns.Fqdn(host)
	defer s.challMu.RUnlock()
	return s.dnsMocks.cnameRecords[host]
}

// DeleteDNSCAMERecord deletes any CNAME alias set for the given host.
func (s *ChallSrv) DeleteDNSCNAMERecord(host string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	host = dns.Fqdn(host)
	delete(s.dnsMocks.cnameRecords, host)
}

// AddDNSARecord adds IPv4 addresses that will be returned when querying for
// A records for the given host.
func (s *ChallSrv) AddDNSARecord(host string, addresses []string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	host = dns.Fqdn(host)
	s.dnsMocks.aRecords[host] = append(s.dnsMocks.aRecords[host], addresses...)
}

// DeleteDNSARecord deletes any IPv4 addresses that will be returned when
// querying for A records for the given host.record for the given host.
func (s *ChallSrv) DeleteDNSARecord(host string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	host = dns.Fqdn(host)
	delete(s.dnsMocks.aRecords, host)
}

// GetDNSARecord returns a slice of IPv4 addresses (in string form) that will be
// returned when querying for A records for the given host.
func (s *ChallSrv) GetDNSARecord(host string) []string {
	s.challMu.RLock()
	host = dns.Fqdn(host)
	defer s.challMu.RUnlock()
	return s.dnsMocks.aRecords[host]
}

// AddDNSAAAARecord adds IPv6 addresses that will be returned when querying for
// AAAA records for the given host.
func (s *ChallSrv) AddDNSAAAARecord(host string, addresses []string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	host = dns.Fqdn(host)
	s.dnsMocks.aaaaRecords[host] = append(s.dnsMocks.aaaaRecords[host], addresses...)
}

// DeleteDNSAAAARecord deletes any IPv6 addresses that will be returned when
// querying for A records for the given host.
func (s *ChallSrv) DeleteDNSAAAARecord(host string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	host = dns.Fqdn(host)
	delete(s.dnsMocks.aaaaRecords, host)
}

// GetDNSAAAARecord returns a slice of IPv6 addresses (in string form) that will
// be returned when querying for A records for the given host.
func (s *ChallSrv) GetDNSAAAARecord(host string) []string {
	s.challMu.RLock()
	defer s.challMu.RUnlock()
	host = dns.Fqdn(host)
	return s.dnsMocks.aaaaRecords[host]
}

// AddDNSCAARecord adds mock CAA records that will be returned when querying
// CAA for the given host.
func (s *ChallSrv) AddDNSCAARecord(host string, policies []MockCAAPolicy) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	host = dns.Fqdn(host)
	s.dnsMocks.caaRecords[host] = append(s.dnsMocks.caaRecords[host], policies...)
}

// DeleteDNSCAARecord deletes any CAA policies that will be returned when
// querying CAA for the given host.
func (s *ChallSrv) DeleteDNSCAARecord(host string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	host = dns.Fqdn(host)
	delete(s.dnsMocks.caaRecords, host)
}

// GetDNSCAARecord returns a slice of mock CAA policies that will
// be returned when querying CAA for the given host.
func (s *ChallSrv) GetDNSCAARecord(host string) []MockCAAPolicy {
	s.challMu.RLock()
	defer s.challMu.RUnlock()
	host = dns.Fqdn(host)
	return s.dnsMocks.caaRecords[host]
}
