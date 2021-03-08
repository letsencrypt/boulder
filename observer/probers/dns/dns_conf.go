package observer

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	p "github.com/letsencrypt/boulder/observer/probers"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v2"
)

var (
	validProtos = []string{"udp", "tcp"}
	validQTypes = map[string]uint16{"A": 1, "TXT": 16, "AAAA": 28, "CAA": 257}
)

// DNSConf is exported to receive the supplied probe config
type DNSConf struct {
	Proto   string `yaml:"protocol"`
	Server  string `yaml:"server"`
	Recurse bool   `yaml:"recurse"`
	QName   string `yaml:"query_name"`
	QType   string `yaml:"query_type"`
}

// UnmarshalSettings takes yaml as bytes and unmarshals it to the
// to a DNSConf object
func (c DNSConf) UnmarshalSettings(settings []byte) (p.Configurer, error) {
	var conf DNSConf
	err := yaml.Unmarshal(settings, &conf)
	if err != nil {
		return nil, err
	}
	return conf, nil
}

// normalize trims and lowers the string fields of `DNSConf`
func (c DNSConf) normalize() {
	c.Proto = strings.Trim(strings.ToLower(c.Proto), " ")
	c.QName = strings.Trim(strings.ToLower(c.QName), " ")
	c.Server = strings.Trim(strings.ToLower(c.Server), " ")
	c.QType = strings.Trim(strings.ToLower(c.QType), " ")
}

func (c DNSConf) validateServer() error {
	schemeExp := regexp.MustCompile("^([[:alnum:]]+://)(.*)+$")
	// ensure `server` does not contain scheme
	if schemeExp.MatchString(c.Server) {
		return fmt.Errorf(
			"invalid `server`, %q, remove %q", c.Server,
			strings.SplitAfter(c.Server, "://")[0])
	}

	servExp := regexp.MustCompile("^(.*)+([[:alnum:]])+(:)([[:digit:]]{1,5})$")
	// ensure `server` contains a port
	if !servExp.MatchString(c.Server) {
		return fmt.Errorf(
			"invalid `server`, %q, missing a port", c.Server)
	}
	// ensure the `server` port provided is a valid port
	servExpMatches := servExp.FindAllStringSubmatch(c.Server, -1)
	port, _ := strconv.Atoi(servExpMatches[0][4])
	if !(port > 0 && port < 65535) {
		return fmt.Errorf(
			"invalid `server`, %q, is not a valid port", port)
	}
	// ensure `server` is a valid fqdn or ipv4/ipv6 address
	host := servExpMatches[0][1]
	ipv6 := net.ParseIP(host).To16()
	ipv4 := net.ParseIP(host).To4()
	fqdn := dns.IsFqdn(dns.Fqdn(host))
	if ipv6 == nil && ipv4 == nil && fqdn != true {
		return fmt.Errorf(
			"invalid `server`, %q, is not an fqdn or ipv4/6 address", c.Server)
	}
	return nil
}

func (c DNSConf) validateProto() error {
	for _, i := range validProtos {
		if c.Proto == i {
			return nil
		}
	}
	return fmt.Errorf(
		"invalid `protocol`, got: %q, expected one in: %s", c.Proto, validProtos)
}

func (c DNSConf) validateQType() error {
	q := make([]string, 0, len(validQTypes))
	for i := range validQTypes {
		q = append(q, i)
		if c.QType == i {
			return nil
		}
	}
	return fmt.Errorf(
		"invalid `query_type`, got: %q, expected one in %s", c.QType, q)
}

// Validate normalizes and validates the received `DNSConf`. If the
// `DNSConf` cannot be validated, an error appropriate for end-user
// consumption is returned
func (c DNSConf) Validate() error {
	c.normalize()

	// validate `query_name`
	if !dns.IsFqdn(dns.Fqdn(c.QName)) {
		return fmt.Errorf("invalid `query_name`, %q is not an fqdn", c.QName)
	}

	// validate `server`
	err := c.validateServer()
	if err != nil {
		return err
	}

	// validate `protocol`
	err = c.validateProto()
	if err != nil {
		return err
	}

	// validate `query_type`
	err = c.validateQType()
	if err != nil {
		return err
	}
	return nil
}

// AsProbe returns the `Conf` object as a DNS probe
func (c DNSConf) AsProbe() p.Prober {
	return DNSProbe{
		Proto:   c.Proto,
		Recurse: c.Recurse,
		QName:   c.QName,
		Server:  c.Server,
		QType:   validQTypes[c.QType],
	}
}

// init is called at runtime and registers `DNSConf`, a probe
// `Configurer` type, as "DNS"
func init() {
	p.Register("DNS", DNSConf{})
}
