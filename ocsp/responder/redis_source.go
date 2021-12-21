package responder

import (
	"context"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/rocsp"
	"golang.org/x/crypto/ocsp"
)

type redisSource struct {
	client *rocsp.Client
	// Note: this logger is not currently used, as all audit log events are from
	// the dbSource right now, but it should and will be used in the future.
	log blog.Logger
	// TODO: Add redis-specific metrics.
}

// NewRedisSource returns a dbSource which will look up OCSP responses in a
// Redis table.
func NewRedisSource(client *rocsp.Client, log blog.Logger) (Source, error) {
	return &redisSource{
		client: client,
		log:    log,
	}, nil
}

// Response implements the Source interface. It looks up the requested OCSP
// response in the redis cluster.
func (src *redisSource) Response(ctx context.Context, req *ocsp.Request) (*Response, error) {
	serialString := core.SerialToString(req.SerialNumber)

	respBytes, err := src.client.GetResponse(ctx, serialString)
	if err != nil {
		return nil, err
	}

	resp, err := ocsp.ParseResponse(respBytes, nil)
	if err != nil {
		return nil, err
	}

	return &Response{Response: resp, Raw: respBytes}, nil
}
