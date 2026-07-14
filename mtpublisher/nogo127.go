//go:build !go1.27

package mtpublisher

import (
	"context"
	"errors"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/letsencrypt/boulder/db"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/trees/tilestore"
)

// SourceConfig mirrors the go1.27 definition so the command builds on go1.26.
type SourceConfig struct {
	Origin      string
	VerifierKey string
}

// MirrorConfig mirrors the go1.27 definition so the command builds on go1.26.
type MirrorConfig struct {
	ID          string
	BaseURL     string
	Name        string
	VerifierKey string
	Tier1       bool
}

// MTPublisher is a stub on go1.26. The real publisher validates ML-DSA-44
// cosignatures, which needs crypto/mldsa (go1.27).
type MTPublisher struct{}

// New always errors on go1.26.
func New(dbMap *db.WrappedMap, interval time.Duration, mtcLogID string, source SourceConfig, mirrors []MirrorConfig, quorum int, srcBackend tilestore.Backend, stats prometheus.Registerer, clk clock.Clock, log blog.Logger) (*MTPublisher, error) {
	return nil, errors.New("boulder-mtpublisher requires go1.27 for crypto/mldsa")
}

// Start is a no-op on go1.26.
func (p *MTPublisher) Start(ctx context.Context) {}
