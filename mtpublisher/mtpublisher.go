//go:build go1.27

package mtpublisher

import (
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
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
	mirrorName     string
	mirrorKeyID    uint32
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
	cosigner, err := cosignature.NewCosigner(mirrorID, mtcLogID, signer)
	if err != nil {
		return nil, fmt.Errorf("creating mirror cosigner: %s", err)
	}
	verifier, err := cosignature.NewVerifier(mirrorID, pubKey)
	if err != nil {
		return nil, fmt.Errorf("creating mirror verifier: %s", err)
	}

	// The mirror's key ID per c2sp.org/tlog-cosignature, repeated from
	// trees/cosignature for the stub's mirror half like the line encoding in
	// cosignatureLine.
	mirrorName := "oid/1.3.6.1.4.1." + mirrorID
	h := sha256.New()
	h.Write([]byte(mirrorName))
	h.Write([]byte{'\n', 0x06})
	h.Write(pubKey.Bytes())
	mirrorKeyID := binary.BigEndian.Uint32(h.Sum(nil)[:4])

	return &publisher{
		db:             dbMap,
		interval:       interval,
		mtcLogID:       mtcLogID,
		origin:         cosigner.Origin(),
		mirrorID:       mirrorID,
		mirrorName:     mirrorName,
		mirrorKeyID:    mirrorKeyID,
		mirrorCosigner: cosigner,
		verifier:       verifier,
		log:            log,
	}, nil
}

type checkpointEntry struct {
	ID              int64  `db:"id"`
	MTCLogID        string `db:"mtcLogID"`
	MTCASignature   []byte `db:"mtcaSignature"`
	MirrorID        string `db:"mirrorID"`
	MirrorSignature []byte `db:"mirrorSignature"`
	TreeSize        int64  `db:"treeSize"`
	RootHash        []byte `db:"rootHash"`
}

// cosign cosigns the checkpoint described by tree as the mirror and returns the
// signature line it would send to the publisher.
//
//   - https://c2sp.org/tlog-cosignature
//   - https://c2sp.org/tlog-mirror
func (p *publisher) cosign(tree tlog.Tree) (string, error) {
	timestampedCosignature, err := p.mirrorCosigner.CosignCheckpoint(tree)
	if err != nil {
		return "", err
	}
	idSignature := make([]byte, 4+len(timestampedCosignature))
	binary.BigEndian.PutUint32(idSignature[:4], p.mirrorKeyID)
	copy(idSignature[4:], timestampedCosignature)
	return "— " + p.mirrorName + " " + base64.StdEncoding.EncodeToString(idSignature) + "\n", nil
}

// Publish cosigns the latest checkpoint in the database if it lacks a mirror
// cosignature and stores the raw signature in the database. Start calls it at
// each interval.
func (p *publisher) Publish(ctx context.Context) error {
	var latest checkpointEntry
	err := p.db.SelectOne(ctx, &latest,
		`SELECT id, checkpoints.mtcLogID, mtcaSignature, mirrorID,
		        mirrorSignature, treeSize, rootHash
		 FROM latestCheckpoint JOIN checkpoints
		 USING(id)
		 WHERE latestCheckpoint.mtcLogID = ? AND
		       checkpoints.mtcLogID = ?`,
		p.mtcLogID,
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

	if len(latest.RootHash) != tlog.HashSize {
		return fmt.Errorf("checkpoint %d root hash is %d bytes, want %d", latest.ID, len(latest.RootHash), tlog.HashSize)
	}
	tree := tlog.Tree{N: latest.TreeSize, Hash: tlog.Hash(latest.RootHash)}

	// The mirror's half of the exchange.
	cosigLine, err := p.cosign(tree)
	if err != nil {
		return fmt.Errorf("cosigning checkpoint %d (%s size %d): %w", latest.ID, latest.MTCLogID, latest.TreeSize, err)
	}
	p.log.Infof("Cosigned checkpoint %d (%s size %d)", latest.ID, latest.MTCLogID, latest.TreeSize)

	// The publisher's half of the exchange.
	cp := checkpoint.Checkpoint{Origin: p.origin, Tree: tree}
	text, err := cp.Marshal()
	if err != nil {
		return fmt.Errorf("marshaling checkpoint %d (%s size %d): %w", latest.ID, latest.MTCLogID, latest.TreeSize, err)
	}
	timestampedMirrorCosig, err := cosignature.TimestampedSignature(text, cosigLine, p.verifier)
	if err != nil {
		return fmt.Errorf("checkpoint %d cosignature failed verification before storage: %w", latest.ID, err)
	}
	mirrorCosig, err := cosignature.RawSignature(timestampedMirrorCosig)
	if err != nil {
		return fmt.Errorf("checkpoint %d cosignature: %w", latest.ID, err)
	}
	_, err = p.db.ExecContext(ctx,
		"UPDATE checkpoints SET mirrorID = ?, mirrorSignature = ? WHERE id = ? AND mtcLogID = ?",
		p.mirrorID, mirrorCosig, latest.ID, p.mtcLogID)
	if err != nil {
		return fmt.Errorf("storing checkpoint %d cosignature (%s size %d): %w", latest.ID, latest.MTCLogID, latest.TreeSize, err)
	}
	p.log.Infof("Stored mirror cosignature for checkpoint %d (%s size %d)", latest.ID, latest.MTCLogID, latest.TreeSize)
	return nil
}

// Start attempts to cosign the latest checkpoint at each interval until ctx is
// cancelled.
func (p *publisher) Start(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		err := p.Publish(ctx)
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
