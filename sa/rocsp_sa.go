package sa

import (
	"context"
	"time"

	rocsp_config "github.com/letsencrypt/boulder/rocsp/config"
)

type RocspWriteSource interface {
	StoreResponse(ctx context.Context, respBytes []byte, shortIssuerID byte, ttl time.Duration) error
}

// storeOCSPRedis spawns a goroutine to store an OCSP response in a redis
// cluster returning errors on an error channel.
func (ssa *SQLStorageAuthority) storeOCSPRedis(ctx context.Context, resp []byte, issuerID int64, ttl time.Duration) error {
	shortIssuerID, err := rocsp_config.FindIssuerByID(issuerID, ssa.shortIssuers)
	if err != nil {
		ssa.redisStoreResponse.WithLabelValues("find_issuer_error").Inc()
		// Log error if FindIssuerByID failed. This should be rare
		// and the logged message will help identify a
		// misconfiguration quickly.
		ssa.log.Errf("failed to FindIssuerByID: %v", err)
		return err
	}
	err = ssa.rocspWriteClient.StoreResponse(ctx, resp, shortIssuerID.ShortID(), ttl)
	if err != nil {
		// Increment error metric. No error log here to prevent
		// spamming syslog in case of down cluster.
		ssa.redisStoreResponse.WithLabelValues("store_response_error").Inc()
		return err
	}
	ssa.redisStoreResponse.WithLabelValues("success").Inc()
	return nil
}
