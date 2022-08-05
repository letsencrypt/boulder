package probers

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/letsencrypt/boulder/crl/crl_x509"
	"github.com/prometheus/client_golang/prometheus"
)

type CRLProber struct {
	url string
	cNextUpdate prometheus.GaugeVec
	cThisUpdate prometheus.GaugeVec
	cCertCount prometheus.GaugeVec
}

func (p CRLProber) Name() string {
	return p.url
}

func (p CRLProber) Kind() string {
	return "CRL"
}

func (p CRLProber) Probe(timeout time.Duration) (bool, time.Duration) {
	start := time.Now()
	resp, err := http.Get(p.url)
	if err != nil {
		fmt.Println(err)
		return false, time.Since(start)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, time.Since(start)
	}

	crl, err := crl_x509.ParseRevocationList(body)
	if err != nil {
		return false, time.Since(start)
	}

	p.cThisUpdate.WithLabelValues(p.url).Set(float64(crl.ThisUpdate.Unix()))
	p.cNextUpdate.WithLabelValues(p.url).Set(float64(crl.NextUpdate.Unix()))
	p.cCertCount.WithLabelValues(p.url).Set(float64(len(crl.RevokedCertificates)))

	return true, time.Since(start)
}
