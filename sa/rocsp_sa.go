package sa

import (
	"context"
	"time"

	rocsp_config "github.com/letsencrypt/boulder/rocsp/config"
	"golang.org/x/crypto/ocsp"
)

type rocspWriter interface {
	StoreResponse(ctx context.Context, respBytes []byte, shortIssuerID byte, ttl time.Duration) error
}

// storeOCSPRedis stores an OCSP response in a redis cluster.
func (ssa *SQLStorageAuthority) storeOCSPRedis(ctx context.Context, resp []byte, issuerID int64) error {
	nextUpdate, err := getNextUpdate(resp)
	if err != nil {
		ssa.redisStoreResponse.WithLabelValues("parse_response_error").Inc()
		return err
	}
	ttl := time.Until(nextUpdate)

	shortIssuerID, err := rocsp_config.FindIssuerByID(issuerID, ssa.shortIssuers)
	if err != nil {
		ssa.redisStoreResponse.WithLabelValues("find_issuer_error").Inc()
		return err
	}
	err = ssa.rocspWriteClient.StoreResponse(ctx, resp, shortIssuerID.ShortID(), ttl)
	if err != nil {
		ssa.redisStoreResponse.WithLabelValues("store_response_error").Inc()
		return err
	}
	ssa.redisStoreResponse.WithLabelValues("success").Inc()
	return nil
}

// getNextUpdate returns the NextUpdate value from the OCSP response.
func getNextUpdate(resp []byte) (time.Time, error) {
	response, err := ocsp.ParseResponse(resp, nil)
	if err != nil {
		return time.Time{}, err
	}
	return response.NextUpdate, nil
}
