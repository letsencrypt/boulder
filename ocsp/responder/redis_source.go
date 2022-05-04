package responder

import (
	"context"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/rocsp"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"
)

type redisSource struct {
	client  *rocsp.Client
	counter *prometheus.CounterVec
	// Note: this logger is not currently used, as all audit log events are from
	// the dbSource right now, but it should and will be used in the future.
	log blog.Logger
}

// NewRedisSource returns a dbSource which will look up OCSP responses in a
// Redis table.
func NewRedisSource(client *rocsp.Client, stats prometheus.Registerer, log blog.Logger) (*redisSource, error) {
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ocsp_redis_responses",
		Help: "Count of OCSP requests/responses by action taken by the redisSource",
	}, []string{"result"})
	stats.MustRegister(counter)

	return &redisSource{
		client:  client,
		counter: counter,
		log:     log,
	}, nil
}

// Response implements the Source interface. It looks up the requested OCSP
// response in the redis cluster.
func (src *redisSource) Response(ctx context.Context, req *ocsp.Request) (*Response, error) {
	serialString := core.SerialToString(req.SerialNumber)

	respBytes, err := src.client.GetResponse(ctx, serialString)
	if err != nil {
		src.counter.WithLabelValues("lookup_error").Inc()
		return nil, err
	}

	resp, err := ocsp.ParseResponse(respBytes, nil)
	if err != nil {
		src.counter.WithLabelValues("parse_error").Inc()
		return nil, err
	}

	src.counter.WithLabelValues("success").Inc()
	return &Response{Response: resp, Raw: respBytes}, nil
}
