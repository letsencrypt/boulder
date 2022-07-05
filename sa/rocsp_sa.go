package sa

import (
	"context"
)

type rocspWriter interface {
	StoreResponse(ctx context.Context, respBytes []byte) error
}

// storeOCSPRedis stores an OCSP response in a redis cluster.
func (ssa *SQLStorageAuthority) storeOCSPRedis(ctx context.Context, resp []byte) error {
	err := ssa.rocspWriteClient.StoreResponse(ctx, resp)
	if err != nil {
		ssa.redisStoreResponse.WithLabelValues("store_response_error").Inc()
		return err
	}
	ssa.redisStoreResponse.WithLabelValues("success").Inc()
	return nil
}
