package probers

import (
	"github.com/letsencrypt/boulder/observer/probers"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v3"
)

type CRLConfigurer struct {
	URL    string               `yaml:"url"`
}

func (c CRLConfigurer) UnmarshalSettings(settings []byte) (probers.Configurer, error) {
	var conf CRLConfigurer
	err := yaml.Unmarshal(settings, &conf)
	if err != nil {
		return nil, err
	}
	return conf, nil
}

// AddCollectors creates all of the `Collector` objects that any `Prober`
// object of the configured type will need, if they do not already exist in
// `probers.ProberCollectors`. If new `Collector` objects are created, they are
// added to `probers.ProberCollectors`
func (c CRLConfigurer) AddCollectors() {
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

func (c CRLConfigurer) MakeProber() (probers.Prober, error) {
	c.AddCollectors()
	nu := probers.ProberCollectors["obs_crl_next_update"].(*prometheus.GaugeVec)
	tu := probers.ProberCollectors["obs_crl_this_update"].(*prometheus.GaugeVec)
	rcc := probers.ProberCollectors["obs_crl_revoked_cert_count"].(*prometheus.GaugeVec)
	return CRLProber{ c.URL, *nu, *tu, *rcc}, nil
}

func init() {
	probers.Register("CRL", CRLConfigurer{})
}
