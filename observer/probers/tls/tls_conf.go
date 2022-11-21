package probers

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/letsencrypt/boulder/observer/probers"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v3"
)

const (
	certExpiryName = "obs_cert_expiry"
	outcomeName    = "tls_prober_outcome"
)

// TLSConf is exported to receive YAML configuration.
type TLSConf struct {
	URL      string `yaml:"url"`
	RootOrg  string `yaml:"rootOrg"`
	RootCN   string `yaml:"rootCN"`
	Response string `yaml:"response"`
}

// Kind returns a name that uniquely identifies the `Kind` of `Configurer`.
func (c TLSConf) Kind() string {
	return "TLS"
}

// UnmarshalSettings takes YAML as bytes and unmarshals it to the to an TLSConf
// object.
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
			"invalid 'url', got %q, expected a valid url: %s", c.URL, err)
	}
	if url.Scheme == "" {
		return fmt.Errorf(
			"invalid 'url', got: %q, missing scheme", c.URL)
	}
	return nil
}

func (c TLSConf) validateResponse() error {
	acceptable := []string{"valid", "expired", "revoked"}
	for _, a := range acceptable {
		if strings.ToLower(c.Response) == a {
			return nil
		}
	}
	return fmt.Errorf(
		"invalid `response`, got %q. Must be one of %s", c.Response, acceptable)

}

// MakeProber constructs a `TLSProbe` object from the contents of the bound
// `TLSConf` object. If the `TLSConf` cannot be validated, an error appropriate
// for end-user consumption is returned instead.
func (c TLSConf) MakeProber(collectors map[string]prometheus.Collector) (probers.Prober, error) {
	// Validate `url`
	err := c.validateURL()
	if err != nil {
		return nil, err
	}

	// Valid `response`
	err = c.validateResponse()
	if err != nil {
		return nil, err
	}

	// Set default Root Organization if none set.
	if c.RootOrg == "" {
		c.RootOrg = "Internet Security Research Group"
	}

	// Validate the Prometheus collectors that were passed in
	coll, ok := collectors[certExpiryName]
	if !ok {
		return nil, fmt.Errorf("tls prober did not receive collector %q", certExpiryName)
	}
	certExpiryColl, ok := coll.(*prometheus.GaugeVec)
	if !ok {
		return nil, fmt.Errorf("tls prober received collector %q of wrong type, got: %T, expected *prometheus.GaugeVec", certExpiryName, coll)
	}

	coll, ok = collectors[outcomeName]
	if !ok {
		return nil, fmt.Errorf("tls prober did not receive collector %q", outcomeName)
	}
	outcomeColl, ok := coll.(*prometheus.GaugeVec)
	if !ok {
		return nil, fmt.Errorf("tls prober received collector %q of wrong type, got: %T, expected *prometheus.GaugeVec", outcomeName, coll)
	}

	return TLSProbe{c.URL, c.RootOrg, c.RootCN, strings.ToLower(c.Response), certExpiryColl, outcomeColl}, nil
}

// Instrument constructs any `prometheus.Collector` objects the `TLSProbe` will
// need to report its own metrics. A map is returned containing the constructed
// objects, indexed by the name of the Promtheus metric.  If no objects were
// constructed, nil is returned.
func (c TLSConf) Instrument() map[string]prometheus.Collector {
	certExpiry := prometheus.Collector(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: certExpiryName,
			Help: "Time to cert expiry in seconds",
		}, []string{"url"},
	))
	outcome := prometheus.Collector(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: outcomeName,
			Help: fmt.Sprintf("Outcome for TLS Prober. Can be one of %s", getReasons()),
		}, []string{"url", "badOutcomeError"},
	))
	return map[string]prometheus.Collector{
		certExpiryName: certExpiry,
		outcomeName:    outcome,
	}
}

// init is called at runtime and registers `TLSConf`, a `Prober` `Configurer`
// type, as "TLS".
func init() {
	probers.Register(TLSConf{})
}
