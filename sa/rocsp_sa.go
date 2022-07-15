package sa

import (
	"context"

	"golang.org/x/crypto/ocsp"
)

type rocspWriter interface {
	StoreResponse(ctx context.Context, response *ocsp.Response) error
}

// storeOCSPRedis stores an OCSP response in a redis cluster.
func (ssa *SQLStorageAuthority) storeOCSPRedis(ctx context.Context, resp []byte) error {
	response, err := ocsp.ParseResponse(resp, nil)
	if err != nil {
		return err
	}
	err = ssa.rocspWriteClient.StoreResponse(ctx, response)
	if err != nil {
		ssa.redisStoreResponse.WithLabelValues("store_response_error").Inc()
		return err
	}
	ssa.redisStoreResponse.WithLabelValues("success").Inc()
	return nil
}
