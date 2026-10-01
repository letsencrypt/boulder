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
	if c.TreeSize <= 0 {
		return fmt.Errorf("TreeSize of %d is invalid", c.TreeSize)
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
	return len(c.MTCASignature) > 0 && c.MirrorID != nil && len(c.MirrorSignature) > 0
}

type CheckpointSubtreeModel struct {
	ID              int64   `db:"id"`
	MTCLogID        string  `db:"mtcLogID"`
	MTCASignature   []byte  `db:"mtcaSignature"`
	MirrorID        *string `db:"mirrorID"`
	MirrorSignature []byte  `db:"mirrorSignature"`
	SubtreeStart    uint64  `db:"subtreeStart"`
	SubtreeEnd      uint64  `db:"subtreeEnd"`
	SubtreeHash     []byte  `db:"subtreeHash"`
}

func (s *CheckpointSubtreeModel) Valid() error {
	if len(s.MTCLogID) == 0 {
		return errors.New("MTCLogID is empty")
	}
	if s.SubtreeEnd <= s.SubtreeStart ||
		s.SubtreeEnd >= 1<<48 {
		return fmt.Errorf("Subtree [%d, %d) is invalid", s.SubtreeStart, s.SubtreeEnd)
	}
	if len(s.SubtreeHash) == 0 {
		return errors.New("SubtreeHash is empty")
	}
	if len(s.SubtreeHash) != sha256.Size {
		return fmt.Errorf("SubtreeHash is %d bytes", len(s.SubtreeHash))
	}

	return nil
}

func (s *CheckpointSubtreeModel) Mirrored() bool {
	return len(s.MTCASignature) > 0 && s.MirrorID != nil && len(s.MirrorSignature) > 0
}

type Impl struct {
	db *db.WrappedMap
}

// New returns an `*Impl` object that uses the given *db.WrappedMap. As a side effect, it registers
// table mappings with borp.
func New(dbMap *db.WrappedMap) *Impl {
	dbMap.AddTableWithName(CheckpointModel{}, "checkpoints").SetKeys(true, "ID")
	dbMap.AddTableWithName(CheckpointSubtreeModel{}, "checkpointSubtrees").SetKeys(true, "ID")
	return &Impl{dbMap}
}

func (i *Impl) LatestCheckpoint(ctx context.Context, mtcLogID string) (*CheckpointModel, error) {
	var latest CheckpointModel
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
	return &latest, nil
}

// InsertCheckpoint inserts the given CheckpointModel into the database.
//
// It modifies its parameter's ID field to set the newly allocated autoincrement ID.
func (i *Impl) InsertCheckpoint(ctx context.Context, c *CheckpointModel) error {
	return i.db.Insert(ctx, c)
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

func (i *Impl) GetCheckpointSubtree(ctx context.Context, mtcLogID string, id int64) (*CheckpointSubtreeModel, error) {
	var checkpointSubtree CheckpointSubtreeModel
	err := i.db.SelectOne(ctx, &checkpointSubtree,
		`SELECT id, mtcLogID, mtcaSignature,
				mirrorID, mirrorSignature,
				subtreeStart, subtreeEnd, subtreeHash
		 FROM checkpointSubtrees
		 WHERE mtcLogID = ? AND
		 	id = ?`,
		mtcLogID,
		id)
	if err != nil {
		return nil, err
	}
	return &checkpointSubtree, nil
}

// InsertCheckpointSubtree inserts a row into db, and returns the inserted row
// ID, or an error. Because borp's `Insert` modifies its argument to set the ID
// when a field is marked as autoincrement (`.SetKeys(true, "ID")`), this method
// also modifies its argument (in this case, `model`).
func (i *Impl) InsertCheckpointSubtree(ctx context.Context, model *CheckpointSubtreeModel) (int64, error) {
	err := i.db.Insert(ctx, model)
	if err != nil {
		return 0, fmt.Errorf("inserting into checkpointSubtrees table: %s", err)
	}

	return model.ID, nil
}

// WithTransaction calls `github.com/letsencrypt/boulder/db.WithTransaction` for the given
// transaction function, with the built-in DB. In the database-backed implementation this
// is simply a pass-through.
//
// TODO(#8998): Replace TxFunc's `db.Executor` parameter with an interface that defines
// the operations we want to perform inside a transaction, so we can mock those.
func (i *Impl) WithTransaction(ctx context.Context, f db.TxFunc) (any, error) {
	return db.WithTransaction(ctx, i.db, f)
}
