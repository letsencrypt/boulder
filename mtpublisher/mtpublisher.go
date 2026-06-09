package mtpublisher

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/db"
	blog "github.com/letsencrypt/boulder/log"
)

// MTPublisher polls the MTC issuance log for checkpoints that still lack a
// mirror cosignature, and adds a dummy cosignature to them. It is a stub for
// the real MTPublisher.
type MTPublisher struct {
	db       *db.WrappedMap
	interval time.Duration
	mtcLogID string
	mirrorID string
	clk      clock.Clock
	log      blog.Logger
}

// New returns a new *Publisher.
func New(dbMap *db.WrappedMap, interval time.Duration, mtcLogID, mirrorID string, clk clock.Clock, log blog.Logger) (*MTPublisher, error) {
	if interval <= 0 {
		return nil, fmt.Errorf("interval must be positive, got %s", interval)
	}
	if mtcLogID == "" {
		return nil, errors.New("mtcLogID must not be empty")
	}
	if mirrorID == "" {
		return nil, errors.New("mirrorID must not be empty")
	}
	return &MTPublisher{
		db:       dbMap,
		interval: interval,
		mtcLogID: mtcLogID,
		mirrorID: mirrorID,
		clk:      clk,
		log:      log,
	}, nil
}

type pendingCheckpoint struct {
	ID       int64  `db:"id"`
	MTCLogID string `db:"mtcLogID"`
	TreeSize int64  `db:"treeSize"`
}

// dummyCosignature returns a dummy Ed25519 tlog-cosignature: a big-endian
// uint64 timestamp followed by the Ed25519 signature.
func (p *MTPublisher) dummyCosignature() []byte {
	out := make([]byte, 8+ed25519.SignatureSize)
	binary.BigEndian.PutUint64(out[:8], uint64(p.clk.Now().Unix())) //nolint:gosec // G115: a Unix timestamp is non-negative.
	return out
}

func (p *MTPublisher) cosignPending(ctx context.Context) error {
	var pending []pendingCheckpoint
	_, err := p.db.Select(ctx, &pending,
		"SELECT id, mtcLogID, treeSize FROM checkpoints WHERE mtcLogID = ? AND mirrorSignature IS NULL",
		p.mtcLogID)
	if err != nil {
		return fmt.Errorf("selecting checkpoints awaiting a cosignature: %w", err)
	}

	for _, cp := range pending {
		_, err := p.db.ExecContext(ctx,
			"UPDATE checkpoints SET mirrorID = ?, mirrorSignature = ? WHERE id = ? AND mtcLogID = ?",
			p.mirrorID, p.dummyCosignature(), cp.ID, p.mtcLogID)
		if err != nil {
			p.log.Errf("Failed to cosign checkpoint %d (%s size %d): %s", cp.ID, cp.MTCLogID, cp.TreeSize, err)
			continue
		}
		p.log.Infof("Cosigned checkpoint %d (%s size %d)", cp.ID, cp.MTCLogID, cp.TreeSize)
	}
	return nil
}

// Start attempts to cosign pending checkpoints at each interval until ctx is
// cancelled.
func (p *MTPublisher) Start(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		err := p.cosignPending(ctx)
		if err != nil {
			p.log.Errf("Cosigning pass failed: %s", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
