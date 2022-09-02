package probers

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/letsencrypt/boulder/observer/probers"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v3"
)

const (
	nextUpdateName = "obs_crl_next_update"
	thisUpdateName = "obs_crl_this_update"
	certCountName  = "obs_crl_revoked_cert_count"
)

// CRLConf is exported to receive YAML configuration
type CRLConf struct {
	URL string `yaml:"url"`
}

// Kind returns a name that uniquely identifies the `Kind` of `Configurer`.
func (c CRLConf) Kind() string {
	return "CRL"
}

// UnmarshalSettings constructs a CRLConf object from YAML as bytes.
func (c CRLConf) UnmarshalSettings(settings []byte) (probers.Configurer, error) {
	var conf CRLConf
	err := yaml.Unmarshal(settings, &conf)
	if err != nil {
		return nil, err
	}
	return conf, nil
}

func (c CRLConf) validateURL() error {
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

func (c CRLConf) validateCollectors(colls map[string]prometheus.Collector) (*prometheus.GaugeVec, *prometheus.GaugeVec, *prometheus.GaugeVec, error) {
	if colls == nil {
		message := "crl prober defines metrics but received nil collector map"
		return nil, nil, nil, errors.New(message)
	}
	var nu, tu, rcc *prometheus.GaugeVec
	for name, coll := range colls {
		switch name {
		case nextUpdateName:
			_, ok := coll.(*prometheus.GaugeVec)
			if !ok {
				message := fmt.Sprintf("crl prober received collector '%s' of wrong type, got: %T, expected *prometheus.GaugeVec", name, nu)
				return nil, nil, nil, errors.New(message)
			}
			nu = coll.(*prometheus.GaugeVec)
		case thisUpdateName:
			_, ok := coll.(*prometheus.GaugeVec)
			if !ok {
				message := fmt.Sprintf("crl prober received collector '%s' of wrong type, got: %T, expected *prometheus.GaugeVec", name, tu)
				return nil, nil, nil, errors.New(message)
			}
			tu = coll.(*prometheus.GaugeVec)
		case certCountName:
			_, ok := coll.(*prometheus.GaugeVec)
			if !ok {
				message := fmt.Sprintf("crl prober received collector '%s' of wrong type, got: %T, expected *prometheus.GaugeVec", name, rcc)
				return nil, nil, nil, errors.New(message)
			}
			rcc = coll.(*prometheus.GaugeVec)
		default:
			message := fmt.Sprintf("crl prober received unexpected collector '%s'", name)
			return nil, nil, nil, errors.New(message)
		}
	}
	if nu == nil {
		message := fmt.Sprintf("crl prober did not receive collector '%s'", nextUpdateName)
		return nil, nil, nil, errors.New(message)
	}
	if tu == nil {
		message := fmt.Sprintf("crl prober did not receive collector '%s'", thisUpdateName)
		return nil, nil, nil, errors.New(message)
	}
	if rcc == nil {
		message := fmt.Sprintf("crl prober did not receive collector '%s'", certCountName)
		return nil, nil, nil, errors.New(message)
	}
	return nu, tu, rcc, nil
}

// MakeProber constructs a `CRLProbe` object from the contents of the
// bound `CRLConf` object. If the `CRLConf` cannot be validated, an
// error appropriate for end-user consumption is returned instead.
func (c CRLConf) MakeProber(collectors map[string]prometheus.Collector) (probers.Prober, error) { // validate `url` err := c.validateURL()
	// validate `url`
	err := c.validateURL()
	if err != nil {
		return nil, err
	}
	// validate the prometheus collectors that were passed in
	nu, tu, rcc, err := c.validateCollectors(collectors)
	if err != nil {
		return nil, err
	}
	return CRLProbe{c.URL, nu, tu, rcc}, nil
}

// Instrument constructs any `prometheus.Collector` objects the `CRLProbe` will
// need to report its own metrics. A map is returned containing the constructed
// objects, indexed by the name of the prometheus metric. If no objects were
// constructed, nil is returned.
func (c CRLConf) Instrument() map[string]prometheus.Collector {
	nextUpdate := prometheus.Collector(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: nextUpdateName,
			Help: "CRL nextUpdate unix timestamp",
		}, []string{"url"},
	))
	thisUpdate := prometheus.Collector(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: thisUpdateName,
			Help: "CRL thisUpdate unix timestamp",
		}, []string{"url"},
	))
	certCount := prometheus.Collector(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: certCountName,
			Help: "number of certificates revoked in CRL",
		}, []string{"url"},
	))
	return map[string]prometheus.Collector{
		nextUpdateName: nextUpdate,
		thisUpdateName: thisUpdate,
		certCountName:  certCount,
	}
}

// init is called at runtime and registers `CRLConf`, a `Prober`
// `Configurer` type, as "CRL".
func init() {
	probers.Register(CRLConf{})
}
