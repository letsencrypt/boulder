package vacfg

import (
	"fmt"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/config"
)

// RetryableErrors configures which transport-layer DoH errors are retryable.
// Each field is a boolean switch; if true, that error category is retryable.
type RetryableErrors struct {
	// Timeout enables retry for context deadline exceeded and net.Error.Timeout().
	// This covers ETIMEDOUT and similar timeout-related errors.
	Timeout *bool
	// Interrupted enables retry for syscall.EINTR (interrupted system call).
	Interrupted *bool
	// WouldBlock enables retry for syscall.EAGAIN and syscall.EWOULDBLOCK
	// (resource temporarily unavailable).
	WouldBlock *bool
	// TooManyFiles enables retry for syscall.EMFILE and syscall.ENFILE
	// (too many open files, file descriptor exhaustion).
	TooManyFiles *bool
	// EOF enables retry for io.EOF and io.ErrUnexpectedEOF.
	EOF *bool
	// ConnReset enables retry for syscall.ECONNRESET.
	ConnReset *bool
	// ConnRefused enables retry for syscall.ECONNREFUSED.
	ConnRefused *bool
	// TLSHandshake enables retry for TLS handshake failures.
	TLSHandshake *bool
	// HTTP429 enables retry for HTTP 429 Too Many Requests responses.
	HTTP429 *bool
	// HTTP5xx enables retry for HTTP 5xx server error responses.
	HTTP5xx *bool
}

// Common contains all of the shared fields for a VA and a Remote VA (RVA).
type Common struct {
	cmd.ServiceConfig
	// UserAgent is the "User-Agent" header sent during http-01 challenges and
	// DoH queries.
	UserAgent string

	IssuerDomain string

	// DNSTries is the number of times to try a DNS query (that has a temporary error)
	// before giving up. May be short-circuited by deadlines. A zero value
	// will be turned into 1.
	DNSTries    int
	DNSProvider *cmd.DNSProvider `validate:"required_without=DNSStaticResolvers"`
	// DNSStaticResolvers is a list of DNS resolvers. Each entry must
	// be a host or IP and port separated by a colon. IPv6 addresses
	// must be enclosed in square brackets.
	DNSStaticResolvers        []string        `validate:"required_without=DNSProvider,dive,hostname_port"`
	DNSTimeout                config.Duration `validate:"required"`
	DNSAllowLoopbackAddresses bool
	// DNSRetryableErrors configures which DoH transport errors should be retried.
	// If nil or unspecified, defaults are applied matching Temporary() behavior.
	DNSRetryableErrors *RetryableErrors

	// AccountURIPrefixes is a list of prefixes used to construct account URIs.
	// The first prefix in the list is used for dns-account-01 challenges.
	// All of the prefixes are used for CAA accounturi validation.
	AccountURIPrefixes []string `validate:"min=1,dive,required,url"`
}

// SetDefaultsAndValidate performs some basic sanity checks on fields stored in
// the Common struct, defaulting them to a sane value when necessary. This
// method does mutate the Common struct.
func (c *Common) SetDefaultsAndValidate(grpcAddr, debugAddr *string) error {
	if *grpcAddr != "" {
		c.GRPC.Address = *grpcAddr
	}
	if *debugAddr != "" {
		c.DebugAddr = *debugAddr
	}

	if c.DNSTimeout.Duration <= 0 {
		return fmt.Errorf("'dnsTimeout' is required")
	}

	if c.DNSTries < 1 {
		c.DNSTries = 1
	}

	return nil
}
