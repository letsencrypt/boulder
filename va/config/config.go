package vacfg

import (
	"fmt"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/config"
)

// Common contains all of the shared fields for a VA and a Remote VA (RVA).
type Common struct {
	cmd.ServiceConfig
	// UserAgent is the "User-Agent" header sent during http-01 challenges and
	// DoH queries.
	UserAgent string

	// IssuerDomain is the CA's issuer domain name, used for:
	//   1. CAA validation: matched against CAA issue/issuewild tag values.
	//   2. dns-persist-01 validation: compared against the issuer-domain-name
	//      in the subscriber's TXT record.
	//
	// Must match the WFE's DirectoryCAAIdentity. A mismatch will cause CAA
	// and dns-persist-01 validation failures.
	IssuerDomain string `validate:"required"`

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

	// AccountURIPrefixes is a list of prefixes used to construct account URIs.
	// The first prefix in the list is used for dns-account-01 and
	// dns-persist-01 challenges.
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
