package probers

import (
	"fmt"
	"net/url"

	"github.com/letsencrypt/boulder/observer/probers"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v3"
)

// TLSConf is exported to receive YAML configuration.
type TLSConf struct {
	URL		string `yaml:"url"`
	Root	string `yaml:"root"`
}

// Kind returns a name that uniquely identifies the `Kind` of `Configurer`.
func (c TLSConf) Kind() string {
	return "TLS"
}

// UnmarshalSettings takes YAML as bytes and unmarshals it to the to an
// TLSConf object.
func (c TLSConf) UnmarshalSettings(settings []byte) (probers.Configurer, error) {
	var conf TLSConf
	err := yaml.Unmarshal(settings, &conf)
	if err != nil {
		return nil, err
	}
	return conf, nil
}

func (c TLSConf) validateURL() error {
	url, err := url.Parse(c.URL)
	if err != nil {
		return fmt.Errorf(
			"invalid 'url', got: %q, expected a valid url", c.URL)
	}
	if url.Scheme == "" {
		return fmt.Errorf(
			"invalid 'url', got: %q, missing scheme", c.URL)
	}
	return nil
}

// MakeProber constructs a `TLSProbe` object from the contents of the
// bound `TLSConf` object. If the `TLSConf` cannot be validated, an
// error appropriate for end-user consumption is returned instead.
func (c TLSConf) MakeProber(_ map[string]prometheus.Collector) (probers.Prober, error) {
	// validate `url`
	err := c.validateURL()
	if err != nil {
		return nil, err
	}

	return TLSProbe{c.URL, c.Root}, nil
}

// Instrument is a no-op to implement the `Configurer` interface.
func (c TLSConf) Instrument() map[string]prometheus.Collector {
	return nil
}

// init is called at runtime and registers `HTTPConf`, a `Prober`
// `Configurer` type, as "HTTP".
func init() {
	probers.Register(TLSConf{})
}
