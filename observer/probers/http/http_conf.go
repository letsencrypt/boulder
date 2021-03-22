package probers

import (
	"fmt"
	"net/url"

	"github.com/letsencrypt/boulder/observer/probers"
	"gopkg.in/yaml.v2"
)

// HTTPConf is exported to receive YAML configuration.
type HTTPConf struct {
	URL    string `yaml:"url"`
	RCodes []int  `yaml:"rcodes"`
}

// UnmarshalSettings takes YAML as bytes and unmarshals it to the
// to an HTTPConf object.
func (c HTTPConf) UnmarshalSettings(settings []byte) (probers.Configurer, error) {
	var conf HTTPConf
	err := yaml.Unmarshal(settings, &conf)
	if err != nil {
		return nil, err
	}
	return conf, nil
}

// Validate ensures the configuration received by `HTTPConf` is valid. If
// the `HTTPConf` cannot be validated, an error appropriate for end-user
// consumption is returned.
func (c HTTPConf) Validate() error {
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

// MakeProber returns a `Prober` object for HTTP requests.
func (c HTTPConf) MakeProber() probers.Prober {
	return HTTPProbe{c.URL, c.RCodes}
}

// init is called at runtime and registers `HTTPConf`, a `Prober`
// `Configurer` type, as "HTTP".
func init() {
	probers.Register("HTTP", HTTPConf{})
}
