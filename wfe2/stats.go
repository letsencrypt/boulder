package wfe2

import (
	"github.com/letsencrypt/boulder/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

type wfe2Stats struct {
	// httpErrorCount counts client errors at the HTTP level
	// e.g. failure to provide a Content-Length header, no POST body, etc
	httpErrorCount *prometheus.CounterVec
	// joseErrorCount counts client errors at the JOSE level
	// e.g. bad JWS, broken JWS signature, invalid JWK, etc
	joseErrorCount *prometheus.CounterVec
}

func initStats(scope metrics.Scope) wfe2Stats {
	httpErrorCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "httpErrors",
			Help: "client request errors at the HTTP level",
		},
		[]string{"type"})
	scope.MustRegister(httpErrorCount)

	joseErrorCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "joseErrors",
			Help: "client request errors at the JOSE level",
		},
		[]string{"type"})
	scope.MustRegister(joseErrorCount)

	return wfe2Stats{
		httpErrorCount: httpErrorCount,
		joseErrorCount: joseErrorCount,
	}
}
