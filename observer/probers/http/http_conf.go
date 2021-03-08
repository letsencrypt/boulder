package observer

import (
	"fmt"
	"net/url"
	"strings"

	p "github.com/letsencrypt/boulder/observer/probers"
	"gopkg.in/yaml.v2"
)

// HTTPConf is exported to receive the supplied probe config
type HTTPConf struct {
	URL    string `yaml:"url"`
	RCodes []int  `yaml:"rcodes"`
}

// UnmarshalSettings takes YAML as bytes and unmarshals it to the
// to a HTTPConf object
func (c HTTPConf) UnmarshalSettings(settings []byte) (p.Configurer, error) {
	var conf HTTPConf
	err := yaml.Unmarshal(settings, &conf)
	if err != nil {
		return nil, err
	}
	return conf, nil
}

// normalize trims and lowers the string fields of `HTTPConf`
func (c HTTPConf) normalize() {
	c.URL = strings.Trim(strings.ToLower(c.URL), " ")
}

// Validate normalizes and validates the received `HTTPConf`. If the
// `DNSConf` cannot be validated, an error appropriate for end-user
// consumption is returned
func (c HTTPConf) Validate() error {
	c.normalize()

	// validate `url`
	url, err := url.Parse(c.URL)
	if err != nil {
		return fmt.Errorf(
			"invalid 'url', got: %q, expected a valid url", c.URL)
	}
	if url.Scheme == "" {
		return fmt.Errorf(
			"invalid 'url', got: %q, missing scheme", c.URL)
	}
	// validate `rcodes`
	if c.RCodes == nil {
		return fmt.Errorf(
			"invalid 'rcodes', got: %q, please specify at least one", c.RCodes)
	}
	return nil
}

// AsProbe returns the NewHTTP object as an HTTP probe
func (c HTTPConf) AsProbe() p.Prober {
	return HTTPProbe{c.URL, c.RCodes}
}

// init is called at runtime and registers `HTTPConf`, a probe
// `Configurer` type, as "HTTP"
func init() {
	p.Register("HTTP", HTTPConf{})
}
