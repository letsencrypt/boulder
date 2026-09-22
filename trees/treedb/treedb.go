package treedb

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"

	"github.com/letsencrypt/boulder/db"
)

var ErrIssuanceLogNotInitialized = errors.New("issuance log DB not initialized")

// CheckpointModel represents the database storage of a checkpoint and associated signatures.
//
// For signing, the TreeSize and RootHash fields are incorporated into a `cosigned.Message`.
type CheckpointModel struct {
	ID              int64   `db:"id"`
	MTCLogID        string  `db:"mtcLogID"`
	MTCASignature   []byte  `db:"mtcaSignature"`
	MirrorID        *string `db:"mirrorID"`
	MirrorSignature []byte  `db:"mirrorSignature"`
	TreeSize        int64   `db:"treeSize"`
	RootHash        []byte  `db:"rootHash"`
	SubtreeID1      *int64  `db:"subtreeID1"`
	SubtreeID2      *int64  `db:"subtreeID2"`
}

func (c *CheckpointModel) Valid() error {
	if len(c.MTCLogID) == 0 {
		return errors.New("MTCLogID is empty")
	}
	if c.TreeSize == 0 {
		return errors.New("TreeSize is 0")
	}
	if len(c.RootHash) == 0 {
		return errors.New("RootHash is empty")
	}
	if len(c.RootHash) != sha256.Size {
		return fmt.Errorf("RootHash is %d bytes", len(c.RootHash))
	}

	return nil
}

func (c *CheckpointModel) Mirrored() bool {
	return len(c.MTCASignature) > 0 && len(c.MirrorSignature) > 0
}

type Impl struct {
	db *db.WrappedMap
}

func (i *Impl) LatestCheckpoint(ctx context.Context, mtcLogID string) (*CheckpointModel, error) {
	latest := new(CheckpointModel)
	err := i.db.SelectOne(ctx, &latest,
		`SELECT id, checkpoints.mtcLogID, mtcaSignature, mirrorID,
		        mirrorSignature, treeSize, rootHash,
		        subtreeID1, subtreeID2
		 FROM latestCheckpoint JOIN checkpoints
		 USING(id)
		 WHERE latestCheckpoint.mtcLogID = ? AND
		       checkpoints.mtcLogID = ?`,
		mtcLogID,
		mtcLogID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("getting latest checkpoint for %q: %w", mtcLogID, ErrIssuanceLogNotInitialized)
		}
		return nil, fmt.Errorf("getting latest checkpoint for %q: %w", mtcLogID, err)
	}
	return latest, nil
}

func (i *Impl) AddMirrorSignature(ctx context.Context, id int64, mirrorID string, mirrorCosig []byte, mtcLogID string) error {
	r, err := i.db.ExecContext(ctx,
		"UPDATE checkpoints SET mirrorID = ?, mirrorSignature = ? WHERE id = ? AND mtcLogID = ?",
		mirrorID, mirrorCosig, id, mtcLogID)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return fmt.Errorf("getting RowsAffected: %s", err)
	}
	if n != 1 {
		return fmt.Errorf("adding mirror signature: %d rows affected (want 1 row affected)", n)
	}
	return nil
}

func New(db *db.WrappedMap) *Impl {
	return &Impl{db}
}
