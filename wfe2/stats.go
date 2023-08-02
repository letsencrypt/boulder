package wfe2

import (
	"github.com/prometheus/client_golang/prometheus"
)

type wfe2Stats struct {
	// httpErrorCount counts client errors at the HTTP level
	// e.g. failure to provide a Content-Length header, no POST body, etc
	httpErrorCount *prometheus.CounterVec
	// joseErrorCount counts client errors at the JOSE level
	// e.g. bad JWS, broken JWS signature, invalid JWK, etc
	joseErrorCount *prometheus.CounterVec
	// csrSignatureAlgs counts the signature algorithms in use for order
	// finalization CSRs
	csrSignatureAlgs *prometheus.CounterVec
	// improperECFieldLengths counts the number of ACME account EC JWKs we see
	// with improper X and Y lengths for their curve
	improperECFieldLengths prometheus.Counter
	// nonceNoMatchingBackendCount counts the number of times we've received a nonce
	// with a prefix that doesn't match a known backend.
	nonceNoMatchingBackendCount prometheus.Counter
}

func initStats(stats prometheus.Registerer) wfe2Stats {
	httpErrorCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_errors",
			Help: "client request errors at the HTTP level",
		},
		[]string{"type"})
	stats.MustRegister(httpErrorCount)

	joseErrorCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "jose_errors",
			Help: "client request errors at the JOSE level",
		},
		[]string{"type"})
	stats.MustRegister(joseErrorCount)

	csrSignatureAlgs := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "csr_signature_algs",
			Help: "Number of CSR signatures by algorithm",
		},
		[]string{"type"},
	)
	stats.MustRegister(csrSignatureAlgs)

	improperECFieldLengths := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "improper_ec_field_lengths",
			Help: "Number of account EC keys with improper X and Y lengths",
		},
	)
	stats.MustRegister(improperECFieldLengths)

	nonceNoBackendCount := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "nonce_no_backend_found",
			Help: "Number of times we've received a nonce with a prefix that doesn't match a known backend",
		},
	)
	stats.MustRegister(nonceNoBackendCount)

	return wfe2Stats{
		httpErrorCount:              httpErrorCount,
		joseErrorCount:              joseErrorCount,
		csrSignatureAlgs:            csrSignatureAlgs,
		improperECFieldLengths:      improperECFieldLengths,
		nonceNoMatchingBackendCount: nonceNoBackendCount,
	}
}
