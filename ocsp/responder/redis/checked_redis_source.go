package redis

import (
	"context"
	"errors"
	"sync"

	"github.com/go-gorp/gorp/v3"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/db"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/ocsp/responder"
	"github.com/letsencrypt/boulder/sa"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"
)

// dbSelector is a limited subset of the db.WrappedMap interface to allow for
// easier mocking of mysql operations in tests.
type dbSelector interface {
	SelectOne(holder interface{}, query string, args ...interface{}) error
	WithContext(ctx context.Context) gorp.SqlExecutor
}

type checkedRedisSource struct {
	base    *redisSource
	dbMap   dbSelector
	counter *prometheus.CounterVec
	log     blog.Logger
}

func NewCheckedRedisSource(base *redisSource, dbMap dbSelector, stats prometheus.Registerer, log blog.Logger) *checkedRedisSource {
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ocsp_db_responses",
		Help: "Count of OCSP requests/responses by action taken by the dbSource",
	}, []string{"result"})
	stats.MustRegister(counter)

	return &checkedRedisSource{
		base:    base,
		dbMap:   dbMap,
		counter: counter,
		log:     log,
	}
}

var ocspCodeToStatus = map[int]core.OCSPStatus{
	ocsp.Good:    core.OCSPStatusGood,
	ocsp.Revoked: core.OCSPStatusRevoked,
}

// Response implements the responder.Source interface. It looks up the requested OCSP
// response in the redis cluster and looks up the corresponding status in the DB. If
// the status disagrees with what redis says, it signs a fresh response and serves it.
func (src *checkedRedisSource) Response(ctx context.Context, req *ocsp.Request) (*responder.Response, error) {
	serialString := core.SerialToString(req.SerialNumber)

	var wg sync.WaitGroup
	wg.Add(2)
	var dbStatus core.CertificateStatus
	var redisResult *responder.Response
	var redisErr, dbErr error
	go func() {
		defer wg.Done()
		dbStatus, dbErr = sa.SelectCertificateStatus(src.dbMap.WithContext(ctx), serialString)
	}()
	go func() {
		defer wg.Done()
		redisResult, redisErr = src.base.Response(ctx, req)
	}()
	wg.Wait()

	if dbErr != nil {
		if db.IsNoRows(dbErr) {
			src.counter.WithLabelValues("not_found").Inc()
			return nil, responder.ErrNotFound
		}

		src.counter.WithLabelValues("db_error").Inc()
		return nil, dbErr
	}

	if redisErr != nil {
		return nil, redisErr
	}

	// If the DB status doesn't match the status returned from the Redis
	// pipeline, the DB is authoritative. Trigger a fresh signing.
	if dbStatus.Status != ocspCodeToStatus[redisResult.Status] ||
		dbStatus.RevokedDate != redisResult.RevokedAt {
		src.counter.WithLabelValues("primary_status_causes_resign").Inc()
		freshResult, err := src.base.signAndSave(ctx, req, serialString)
		if err != nil {
			src.counter.WithLabelValues("sign_and_save_error").Inc()
			return nil, err
		}
		// This could happen for instance with replication lag, or if the
		// RA was talking to a different DB.
		if dbStatus.Status != ocspCodeToStatus[freshResult.Status] {
			src.counter.WithLabelValues("fresh_mismatch").Inc()
			return nil, errors.New("freshly signed status did not match DB")
		}
		return freshResult, nil
	}

	return redisResult, nil
}
