package responder

import (
	"context"
	"encoding/hex"

	"github.com/go-gorp/gorp/v3"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/db"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"
	"golang.org/x/crypto/ocsp"
)

type dbSource struct {
	dbMap dbSelector
	log   blog.Logger
	// TODO: Add sql-specific metrics.
}

// Define an interface with the needed methods from gorp.
// This also allows us to simulate MySQL failures by mocking the interface.
type dbSelector interface {
	SelectOne(holder interface{}, query string, args ...interface{}) error
	WithContext(ctx context.Context) gorp.SqlExecutor
}

// NewDbSource returns a dbSource which will look up OCSP responses in a SQL
// database.
func NewDbSource(dbMap dbSelector, log blog.Logger) (Source, error) {
	return &dbSource{
		dbMap: dbMap,
		log:   log,
	}, nil
}

// Response implements the Source interface. It looks up the requested OCSP
// response in the sql database. If the certificate status row that it finds
// indicates that the cert is expired or this cert has never had an OCSP
// response generated for it, it returns an error.
func (src *dbSource) Response(ctx context.Context, req *ocsp.Request) (*Response, error) {
	serialString := core.SerialToString(req.SerialNumber)

	certStatus, err := sa.SelectCertificateStatus(src.dbMap.WithContext(ctx), serialString)
	if err != nil {
		if db.IsNoRows(err) {
			return nil, ErrNotFound
		}

		src.log.AuditErrf("Looking up OCSP response in DB: %s", err)
		return nil, err
	}

	if certStatus.IsExpired {
		src.log.Infof("OCSP Response not sent (expired) for CA=%s, Serial=%s", hex.EncodeToString(req.IssuerKeyHash), serialString)
		return nil, ErrNotFound
	} else if certStatus.OCSPLastUpdated.IsZero() {
		src.log.Warningf("OCSP Response not sent (ocspLastUpdated is zero) for CA=%s, Serial=%s", hex.EncodeToString(req.IssuerKeyHash), serialString)
		return nil, ErrNotFound
	}

	resp, err := ocsp.ParseResponse(certStatus.OCSPResponse, nil)
	if err != nil {
		return nil, err
	}

	return &Response{Response: resp, Raw: certStatus.OCSPResponse}, nil
}
