package probers

import (
	"fmt"
	"net/url"

	"github.com/letsencrypt/boulder/observer/probers"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v3"
)

type CRLConf struct {
	URL string `yaml:"url"`
}

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

// AddCollectors creates all of the `Collector` objects that any `Prober`
// object of the configured type will need, if they do not already exist in
// `probers.ProberCollectors`. If new `Collector` objects are created, they are
// added to `probers.ProberCollectors`
func (c CRLConf) AddCollectors() {
	nextUpdate := prometheus.Collector(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "obs_crl_next_update",
			Help: "CRL nextUpdate unix timestamp",
		}, []string{"url"},
	))
	thisUpdate := prometheus.Collector(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "obs_crl_this_update",
			Help: "CRL thisUpdate unix timestamp",
		}, []string{"url"},
	))
	certCount := prometheus.Collector(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "obs_crl_revoked_cert_count",
			Help: "number of certificates revoked in CRL",
		}, []string{"url"},
	))
	probers.ProberCollectors["obs_crl_next_update"] = nextUpdate
	probers.ProberCollectors["obs_crl_this_update"] = thisUpdate
	probers.ProberCollectors["obs_crl_revoked_cert_count"] = certCount
}

func (c CRLConf) MakeProber() (probers.Prober, error) {
	// validate `url`
	err := c.validateURL()
	if err != nil {
		return nil, err
	}

	c.AddCollectors()
	nu := probers.ProberCollectors["obs_crl_next_update"].(*prometheus.GaugeVec)
	tu := probers.ProberCollectors["obs_crl_this_update"].(*prometheus.GaugeVec)
	rcc := probers.ProberCollectors["obs_crl_revoked_cert_count"].(*prometheus.GaugeVec)
	return CRLProbe{c.URL, *nu, *tu, *rcc}, nil
}

func init() {
	probers.Register("CRL", CRLConf{})
}
