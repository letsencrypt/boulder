package responder

import (
	"context"
	"errors"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/ocsp/responder"
	"github.com/letsencrypt/boulder/rocsp"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"
)

type rocspClient interface {
	GetResponse(ctx context.Context, serial string) ([]byte, error)
	StoreResponse(ctx context.Context, resp *ocsp.Response) error
}

type redisSource struct {
	client            rocspClient
	signer            responder.Source
	counter           *prometheus.CounterVec
	clk               clock.Clock
	liveSigningPeriod time.Duration
	// Note: this logger is not currently used, as all audit log events are from
	// the dbSource right now, but it should and will be used in the future.
	log blog.Logger
}

// NewRedisSource returns a responder.Source which will look up OCSP responses in a
// Redis table.
func NewRedisSource(
	client *rocsp.WritingClient,
	signer responder.Source,
	liveSigningPeriod time.Duration,
	clk clock.Clock,
	stats prometheus.Registerer,
	log blog.Logger,
) (*redisSource, error) {
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ocsp_redis_responses",
		Help: "Count of OCSP requests/responses by action taken by the redisSource",
	}, []string{"result"})
	stats.MustRegister(counter)

	var rocspReader rocspClient
	if client != nil {
		rocspReader = client
	}
	return &redisSource{
		client:            rocspReader,
		signer:            signer,
		counter:           counter,
		liveSigningPeriod: liveSigningPeriod,
		clk:               clk,
		log:               log,
	}, nil
}

// Response implements the responder.Source interface. It looks up the requested OCSP
// response in the redis cluster.
func (src *redisSource) Response(ctx context.Context, req *ocsp.Request) (*responder.Response, error) {
	serialString := core.SerialToString(req.SerialNumber)

	respBytes, err := src.client.GetResponse(ctx, serialString)
	if err != nil {
		if errors.Is(err, rocsp.ErrRedisNotFound) {
			return src.signAndSave(ctx, req, "not_found_redis")
		}
		src.counter.WithLabelValues("lookup_error").Inc()
		return nil, err
	}

	resp, err := ocsp.ParseResponse(respBytes, nil)
	if err != nil {
		src.counter.WithLabelValues("parse_error").Inc()
		return nil, err
	}

	if src.isStale(resp) {
		src.counter.WithLabelValues("stale").Inc()
		return src.signAndSave(ctx, req, "stale_redis")
	}

	src.counter.WithLabelValues("success").Inc()
	return &responder.Response{Response: resp, Raw: respBytes}, nil
}

func (src *redisSource) isStale(resp *ocsp.Response) bool {
	return src.clk.Since(resp.ThisUpdate) > src.liveSigningPeriod
}

func (src *redisSource) signAndSave(ctx context.Context, req *ocsp.Request, cause string) (*responder.Response, error) {
	resp, err := src.signer.Response(ctx, req)
	if err != nil {
		if errors.Is(err, rocsp.ErrRedisNotFound) {
			src.counter.WithLabelValues(cause + "_certificate_not_found").Inc()
			return nil, responder.ErrNotFound
		}
		src.counter.WithLabelValues(cause + "_signing_error").Inc()
		return nil, err
	}
	src.counter.WithLabelValues(cause + "_signing_success").Inc()
	go src.client.StoreResponse(context.Background(), resp.Response)
	return resp, nil
}
