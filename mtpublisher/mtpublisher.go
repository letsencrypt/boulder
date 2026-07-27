//go:build go1.27

package mtpublisher

import (
	"context"
	"crypto"
	"crypto/mldsa"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/db"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/trees/checkpoint"
	"github.com/letsencrypt/boulder/trees/cosignature"
)

// publisher polls the MTC issuance log and cosigns the latest checkpoint if it
// lacks a mirror cosignature, playing both halves of the future exchange: it
// signs a signature line as the mirror, then ingests it through the note layer
// as the publisher will once the mirror is a separate server. It is a stub for
// the real MTPublisher.
type publisher struct {
	db             *db.WrappedMap
	interval       time.Duration
	mtcLogID       string
	origin         string
	mirrorID       string
	mirrorCosigner *cosignature.Cosigner
	verifier       *cosignature.Verifier
	log            blog.Logger
}

// New returns a publisher that cosigns as the mirror with mirrorID using
// signer, verifying each cosignature against pubKey before storing it.
func New(dbMap *db.WrappedMap, interval time.Duration, mtcLogID, mirrorID string, signer crypto.Signer, pubKey *mldsa.PublicKey, log blog.Logger) (*publisher, error) {
	if interval <= 0 {
		return nil, fmt.Errorf("interval must be positive, got %s", interval)
	}
	origin, err := cosignature.Origin(mtcLogID)
	if err != nil {
		return nil, fmt.Errorf("deriving the log origin: %s", err)
	}
	cosigner, err := cosignature.NewCosigner(mirrorID, mtcLogID, signer)
	if err != nil {
		return nil, fmt.Errorf("creating mirror cosigner: %s", err)
	}
	verifier, err := cosignature.NewVerifier(mirrorID, pubKey)
	if err != nil {
		return nil, fmt.Errorf("creating mirror verifier: %s", err)
	}
	return &publisher{
		db:             dbMap,
		interval:       interval,
		mtcLogID:       mtcLogID,
		origin:         origin,
		mirrorID:       mirrorID,
		mirrorCosigner: cosigner,
		verifier:       verifier,
		log:            log,
	}, nil
}

type checkpointEntry struct {
	ID              int64  `db:"id"`
	MTCLogID        string `db:"mtcLogID"`
	TreeSize        int64  `db:"treeSize"`
	RootHash        []byte `db:"rootHash"`
	MirrorSignature []byte `db:"mirrorSignature"`
}

func (p *publisher) publish(ctx context.Context) error {
	// latestCheckpoint names the checkpoint to cosign, and only ever references
	// a CA-signed one: the sequencer signs and moves the pointer in a single
	// transaction, so an in-flight sequence's precommitted row is not visible
	// here. Both mtcLogID predicates keep the join single-shard under Vitess.
	var latest checkpointEntry
	err := p.db.SelectOne(ctx, &latest, `
		SELECT id, checkpoints.mtcLogID, treeSize, rootHash, mirrorSignature
		FROM latestCheckpoint JOIN checkpoints USING(id)
		WHERE latestCheckpoint.mtcLogID = ? AND checkpoints.mtcLogID = ?`,
		p.mtcLogID, p.mtcLogID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("selecting the latest checkpoint: %w", err)
	}
	if latest.MirrorSignature != nil {
		return nil
	}

	if len(latest.RootHash) != tlog.HashSize {
		return fmt.Errorf("checkpoint %d root hash is %d bytes, want %d", latest.ID, len(latest.RootHash), tlog.HashSize)
	}
	tree := tlog.Tree{N: latest.TreeSize, Hash: tlog.Hash(latest.RootHash)}

	// The mirror's half of the exchange, in place of a tlog-mirror server.
	line, err := p.mirrorCosigner.CosignatureLine(tree)
	if err != nil {
		return fmt.Errorf("cosigning checkpoint %d (%s size %d): %w", latest.ID, latest.MTCLogID, latest.TreeSize, err)
	}

	// The publisher's half of the exchange.
	cp := checkpoint.Checkpoint{Origin: p.origin, Tree: tree}
	text, err := cp.Marshal()
	if err != nil {
		return fmt.Errorf("marshaling checkpoint %d (%s size %d): %w", latest.ID, latest.MTCLogID, latest.TreeSize, err)
	}
	timestampedSignature, err := cosignature.TimestampedSignature(text, line, p.verifier)
	if err != nil {
		return fmt.Errorf("checkpoint %d cosignature failed verification before storage: %w", latest.ID, err)
	}
	signature, err := cosignature.RawSignature(timestampedSignature)
	if err != nil {
		return fmt.Errorf("checkpoint %d cosignature: %w", latest.ID, err)
	}
	_, err = p.db.ExecContext(ctx, `
		UPDATE checkpoints SET mirrorID = ?, mirrorSignature = ?
		WHERE id = ? AND mtcLogID = ?`,
		p.mirrorID, signature, latest.ID, p.mtcLogID)
	if err != nil {
		return fmt.Errorf("cosigning checkpoint %d (%s size %d): %w", latest.ID, latest.MTCLogID, latest.TreeSize, err)
	}
	p.log.Infof("Cosigned checkpoint %d (%s size %d)", latest.ID, latest.MTCLogID, latest.TreeSize)
	return nil
}

// Start attempts to cosign the latest checkpoint at each interval until ctx is
// cancelled.
func (p *publisher) Start(ctx context.Context) {
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
