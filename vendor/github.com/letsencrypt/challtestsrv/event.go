package challtestsrv

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

// RequestEventType indicates what type of event occurred.
type RequestEventType int

const (
	// HTTP requests
	HTTPRequestEventType RequestEventType = iota
	// DNS requests
	DNSRequestEventType
	// TLS-ALPN-01 requests
	TLSALPNRequestEventType
)

// A RequestEvent is anything that can identify its RequestEventType and a key
// for storing the request event in the history.
type RequestEvent interface {
	Type() RequestEventType
	Key() string
}

// HTTPRequestEvent corresponds to an HTTP request received by a httpOneServer.
// It implements the RequestEvent interface.
type HTTPRequestEvent struct {
	// The full request URL (path and query arguments)
	URL string
	// The Host header from the request
	Host string
	// Whether the request was received over HTTPS or HTTP
	HTTPS bool
	// The ServerName from the ClientHello. May be empty if there was no SNI or if
	// the request was not HTTPS
	ServerName string
}

// HTTPRequestEvents always have type HTTPRequestEventType
func (e HTTPRequestEvent) Type() RequestEventType {
	return HTTPRequestEventType
}

// HTTPRequestEvents use the HTTP Host as the storage key. Any explicit port
// will be removed.
func (e HTTPRequestEvent) Key() string {
	if h, _, err := net.SplitHostPort(e.Host); err == nil {
		return h
	}
	return e.Host
}

// DNSRequestEvent corresponds to a DNS request received by a dnsOneServer. It
// implements the RequestEvent interface.
type DNSRequestEvent struct {
	// The DNS question received.
	Question dns.Question
}

// DNSRequestEvents always have type DNSRequestEventType
func (e DNSRequestEvent) Type() RequestEventType {
	return DNSRequestEventType
}

// DNSRequestEvents use the Question Name as the storage key. Any trailing `.`
// in the question name is removed.
func (e DNSRequestEvent) Key() string {
	key := e.Question.Name
	if strings.HasSuffix(key, ".") {
		key = strings.TrimSuffix(key, ".")
	}
	return key
}

// TLSALPNRequestEvent corresponds to a TLS request received by
// a tlsALPNOneServer. It implements the RequestEvent interface.
type TLSALPNRequestEvent struct {
	// ServerName from the TLS Client Hello.
	ServerName string
	// SupportedProtos from the TLS Client Hello.
	SupportedProtos []string
}

// TLSALPNRequestEvents always have type TLSALPNRequestEventType
func (e TLSALPNRequestEvent) Type() RequestEventType {
	return TLSALPNRequestEventType
}

// TLSALPNRequestEvents use the SNI value as the storage key
func (e TLSALPNRequestEvent) Key() string {
	return e.ServerName
}

// AddRequestEvent adds a RequestEvent to the server's request history. It is
// appeneded to a list of RequestEvents indexed by the event's Type().
func (s *ChallSrv) AddRequestEvent(event RequestEvent) {
	s.challMu.Lock()
	defer s.challMu.Unlock()

	typ := event.Type()
	host := event.Key()
	if s.requestHistory[host] == nil {
		s.requestHistory[host] = make(map[RequestEventType][]RequestEvent)
	}
	s.requestHistory[host][typ] = append(s.requestHistory[host][typ], event)
}

// RequestHistory returns the server's request history for the given hostname
// and event type.
func (s *ChallSrv) RequestHistory(hostname string, typ RequestEventType) []RequestEvent {
	s.challMu.RLock()
	defer s.challMu.RUnlock()

	if hostEvents, ok := s.requestHistory[hostname]; ok {
		return hostEvents[typ]
	}
	return []RequestEvent{}
}

// ClearRequestHistory clears the server's request history for the given
// hostname and event type.
func (s *ChallSrv) ClearRequestHistory(hostname string, typ RequestEventType) {
	s.challMu.Lock()
	defer s.challMu.Unlock()

	if hostEvents, ok := s.requestHistory[hostname]; ok {
		hostEvents[typ] = []RequestEvent{}
	}
}
