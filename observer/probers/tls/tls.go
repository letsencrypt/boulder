package probers

import (
	"fmt"
	"time"
	"crypto/tls"
	"github.com/prometheus/client_golang/prometheus"
)

// TLSProbe is the exported 'Prober' object for monitors configured to
// perform TLS protocols.
type TLSProbe struct {
	url			string
	root		string
	response	string
	certExpiry	*prometheus.GaugeVec
}

// Name returns a string that uniquely identifies the monitor.
func (p TLSProbe) Name() string {
	return fmt.Sprintf("%s-%s", p.url, p.root)
}

// Kind returns a name that uniquely identifies the `Kind` of `Prober`.
func (p TLSProbe) Kind() string {
	return "TLS"
}

// Probe performs the configured TLS protocol.
// Return true if both root AND response are the expected values, otherewise false
// Export time to cert expiry as Prometheus metric
func (p TLSProbe) Probe(timeout time.Duration) (bool, time.Duration) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	start := time.Now()
	conn, err := tls.Dial("tcp", p.url, conf)
	if err != nil {
		return false, time.Since(start)
	}
	defer conn.Close()
	chain := conn.ConnectionState().VerifiedChains[0]
	end_cert, root_cert := chain[0], chain[len(chain)-1]
	time_to_expiry := time.Until(end_cert.NotAfter)

	//Report time to expiration (in seconds) for this site
	p.certExpiry.WithLabelValues(p.url).Set(float64(time_to_expiry.Seconds()))

	return root_cert.Issuer.CommonName==p.root, time.Since(start)
}
