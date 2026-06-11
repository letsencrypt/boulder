package mtpublisher

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/db"
	blog "github.com/letsencrypt/boulder/log"
)

// MTPublisher polls the MTC issuance log and adds a dummy cosignature to the
// latest checkpoint if it lacks one. It is a stub for the real MTPublisher.
type MTPublisher struct {
	db       *db.WrappedMap
	interval time.Duration
	mtcLogID string
	mirrorID string
	clk      clock.Clock
	log      blog.Logger
}

// New returns a new *MTPublisher.
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

type checkpointEntry struct {
	ID              int64  `db:"id"`
	MTCLogID        string `db:"mtcLogID"`
	TreeSize        int64  `db:"treeSize"`
	MirrorSignature []byte `db:"mirrorSignature"`
}

// dummyCosignature returns a dummy Ed25519 tlog-cosignature: a big-endian
// uint64 timestamp followed by the Ed25519 signature.
func (p *MTPublisher) dummyCosignature() []byte {
	out := make([]byte, 8+ed25519.SignatureSize)
	binary.BigEndian.PutUint64(out[:8], uint64(p.clk.Now().Unix())) //nolint:gosec // G115: a Unix timestamp is non-negative.
	return out
}

func (p *MTPublisher) publish(ctx context.Context) error {
	var latest checkpointEntry
	err := p.db.SelectOne(ctx, &latest,
		"SELECT id, mtcLogID, treeSize, mirrorSignature FROM checkpoints WHERE mtcLogID = ? ORDER BY treeSize DESC LIMIT 1",
		p.mtcLogID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("selecting the latest checkpoint: %w", err)
	}
	if latest.MirrorSignature != nil {
		return nil
	}

	_, err = p.db.ExecContext(ctx,
		"UPDATE checkpoints SET mirrorID = ?, mirrorSignature = ? WHERE id = ? AND mtcLogID = ?",
		p.mirrorID, p.dummyCosignature(), latest.ID, p.mtcLogID)
	if err != nil {
		return fmt.Errorf("cosigning checkpoint %d (%s size %d): %w", latest.ID, latest.MTCLogID, latest.TreeSize, err)
	}
	p.log.Infof("Cosigned checkpoint %d (%s size %d)", latest.ID, latest.MTCLogID, latest.TreeSize)
	return nil
}

// Start attempts to cosign the latest checkpoint at each interval until ctx is
// cancelled.
func (p *MTPublisher) Start(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		err := p.publish(ctx)
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
