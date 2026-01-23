package probers

import (
	"fmt"
	"net/url"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/letsencrypt/boulder/observer/probers"
	"github.com/letsencrypt/boulder/strictyaml"
)

const (
	notBeforeName = "obs_aia_not_before"
	notAfterName  = "obs_aia_not_after"
)

// AIAConf is exported to receive YAML configuration
type AIAConf struct {
	URL string `yaml:"url"`
}

// Kind returns a name that uniquely identifies the `Kind` of `Configurer`.
func (c AIAConf) Kind() string {
	return "AIA"
}

// UnmarshalSettings constructs a AIAConf object from YAML as bytes.
func (c AIAConf) UnmarshalSettings(settings []byte) (probers.Configurer, error) {
	var conf AIAConf
	err := strictyaml.Unmarshal(settings, &conf)

	if err != nil {
		return nil, err
	}
	return conf, nil
}

func (c AIAConf) validateURL() error {
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

// MakeProber constructs a `AIAProbe` object from the contents of the
// bound `AIAConf` object. If the `AIAConf` cannot be validated, an
// error appropriate for end-user consumption is returned instead.
func (c AIAConf) MakeProber(collectors map[string]prometheus.Collector) (probers.Prober, error) {
	// validate `url`
	err := c.validateURL()
	if err != nil {
		return nil, err
	}

	// validate the prometheus collectors that were passed in
	coll, ok := collectors[notBeforeName]
	if !ok {
		return nil, fmt.Errorf("aia prober did not receive collector %q", notBeforeName)
	}
	notBeforeColl, ok := coll.(*prometheus.GaugeVec)
	if !ok {
		return nil, fmt.Errorf("aia prober received collector %q of wrong type, got: %T, expected *prometheus.GaugeVec", notBeforeName, coll)
	}

	coll, ok = collectors[notAfterName]
	if !ok {
		return nil, fmt.Errorf("aia prober did not receive collector %q", notAfterName)
	}
	notAfterColl, ok := coll.(*prometheus.GaugeVec)
	if !ok {
		return nil, fmt.Errorf("aia prober received collector %q of wrong type, got: %T, expected *prometheus.GaugeVec", notAfterName, coll)
	}

	return AIAProbe{c.URL, notBeforeColl, notAfterColl}, nil
}

// Instrument constructs any `prometheus.Collector` objects the `AIAProbe` will
// need to report its own metrics. A map is returned containing the constructed
// objects, indexed by the name of the prometheus metric. If no objects were
// constructed, nil is returned.
func (c AIAConf) Instrument() map[string]prometheus.Collector {
	notBefore := prometheus.Collector(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: notBeforeName,
			Help: "AIA certificate notBefore Unix timestamp in seconds",
		}, []string{"url"},
	))
	notAfter := prometheus.Collector(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: notAfterName,
			Help: "AIA certificate notAfter Unix timestamp in seconds",
		}, []string{"url"},
	))
	return map[string]prometheus.Collector{
		notBeforeName: notBefore,
		notAfterName:  notAfter,
	}
}

// init is called at runtime and registers `AIAConf`, a `Prober`
// `Configurer` type, as "AIA".
func init() {
	probers.Register(AIAConf{})
}
