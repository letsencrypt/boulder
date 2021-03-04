package observer

import (
	"fmt"
	"net/url"
	"strings"

	p "github.com/letsencrypt/boulder/observer/probes"
	"gopkg.in/yaml.v2"
)

// HTTPConf is exported to receive the supplied probe config
type HTTPConf struct {
	URL   string `yaml:"url"`
	RCode int    `yaml:"rcode"`
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

func (c HTTPConf) normalize() {
	c.URL = strings.Trim(strings.ToLower(c.URL), " ")
}

// Validate normalizes and validates the received probe config
func (c HTTPConf) Validate() error {
	c.normalize()

	// validate `url`
	url, err := url.Parse(c.URL)
	if err != nil {
		return fmt.Errorf(
			"invalid url, got: %q, expected a valid url", c.URL)
	}
	if url.Scheme == "" {
		return fmt.Errorf(
			"invalid url, got: %q, missing scheme", c.URL)
	}
	if c.RCode == 0 {
		return fmt.Errorf(
			"invalid rcode, got: %q, please specify a response code", c.RCode)
	}
	return nil
}

// AsProbe returns the NewHTTP object as an HTTP probe
func (c HTTPConf) AsProbe() p.Prober {
	url, _ := url.Parse(c.URL)
	return HTTPProbe{URL: *url, RCode: c.RCode}
}

// init is called on observer start and registers HTTP as a probe type
func init() {
	p.Register("HTTP", HTTPConf{})
}
