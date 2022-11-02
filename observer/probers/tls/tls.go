package probers

import (
	"fmt"
	"time"
	"crypto/tls"
	// "github.com/prometheus/client_golang/prometheus"
)

// TLSProbe is the exported 'Prober' object for monitors configured to
// perform TLS protocols.
type TLSProbe struct {
	url			string
	root		string
	// certExpiry	*prometheus.GaugeVec
}

// Name returns a string that uniquely identifies the monitor.
func (p TLSProbe) Name() string {
	return fmt.Sprintf("%s", p.url)
}

// Kind returns a name that uniquely identifies the `Kind` of `Prober`.
func (p TLSProbe) Kind() string {
	return "TLS"
}

func (p TLSProbe) rootIsExpected(received string) bool {
	if received == p.root {
		return true
	}
	return false
}

// Probe performs the configured TLS protocol.
func (p TLSProbe) Probe(timeout time.Duration) (bool, time.Duration) {
	// want to return: 
	// a) time to expiration
	// b) correct end entity response (valid, expired, revoked)
	// c) correct cert chain
	// https://stackoverflow.com/questions/31751764/get-remote-ssl-certificate-in-golang
	start := time.Now()

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", p.url, conf)
	if err != nil {
		return false, time.Since(start)
	}
	defer conn.Close()
	chain := conn.ConnectionState().VerifiedChains[0]
	end_cert, root_cert := chain[0], chain[len(chain)-1]
	end_cert_expiry := end_cert.NotAfter
	fmt.Println(end_cert_expiry)

	return p.rootIsExpected(root_cert.Issuer.CommonName), time.Since(start)
}
