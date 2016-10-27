package bdns

import (
	"fmt"
	"net"

	"github.com/letsencrypt/boulder/probs"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

// DNSError wraps a DNS error with various relevant information
type DNSError struct {
	recordType uint16
	hostname   string
	// Exactly one of rCode or underlying should be set.
	underlying error
	rCode      int
}

func (d DNSError) Error() string {
	var detail string
	if d.underlying != nil {
		if netErr, ok := d.underlying.(*net.OpError); ok {
			if netErr.Timeout() {
				detail = detailDNSTimeout
			} else {
				detail = detailDNSNetFailure
			}
			// Note: we check d.underlying here even though `Timeout()` does this because the call to `netErr.Timeout()` above only
			// happens for `*net.OpError` underlying types!
		} else if d.underlying == context.Canceled || d.underlying == context.DeadlineExceeded {
			detail = detailDNSTimeout
		} else {
			detail = detailServerFailure
		}
	} else if d.rCode != dns.RcodeSuccess {
		detail = dns.RcodeToString[d.rCode]
	} else {
		detail = detailServerFailure
	}
	return fmt.Sprintf("DNS problem: %s looking up %s for %s", detail,
		dns.TypeToString[d.recordType], d.hostname)
}

// Timeout returns true if the underlying error was a timeout
func (d DNSError) Timeout() bool {
	if netErr, ok := d.underlying.(*net.OpError); ok {
		return netErr.Timeout()
	} else if d.underlying == context.Canceled || d.underlying == context.DeadlineExceeded {
		return true
	}
	return false
}

const detailDNSTimeout = "query timed out"
const detailDNSNetFailure = "networking error"
const detailServerFailure = "server failure at resolver"

// ProblemDetailsFromDNSError checks the error returned from Lookup...  methods
// and tests if the error was an underlying net.OpError or an error caused by
// resolver returning SERVFAIL or other invalid Rcodes and returns the relevant
// core.ProblemDetails. The detail string will contain a mention of the DNS
// record type and domain given.
func ProblemDetailsFromDNSError(err error) *probs.ProblemDetails {
	if dnsErr, ok := err.(*DNSError); ok {
		return probs.ConnectionFailure(dnsErr.Error())
	}
	return probs.ConnectionFailure(detailServerFailure)
}
