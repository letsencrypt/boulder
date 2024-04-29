package vacfg

import (
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/config"
)

// Common contains all of the shared fields for a VA and a Remote VA (RVA).
type Common struct {
	cmd.ServiceConfig
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

	AccountURIPrefixes []string `validate:"min=1,dive,required,url"`
}
