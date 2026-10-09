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
	CheckpointID    int64   `db:"checkpointID"`
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
		        mirrorSignature, treeSize, rootHash
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

// AddSubtreeMirrorSignature stores the mirror's signature on the checkpoint
// subtree with the given ID.
func (i *Impl) AddSubtreeMirrorSignature(ctx context.Context, id int64, mirrorID string, mirrorSignature []byte, mtcLogID string) error {
	r, err := i.db.ExecContext(ctx,
		"UPDATE checkpointSubtrees SET mirrorID = ?, mirrorSignature = ? WHERE id = ? AND mtcLogID = ?",
		mirrorID, mirrorSignature, id, mtcLogID)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return fmt.Errorf("getting RowsAffected: %s", err)
	}
	if n != 1 {
		return fmt.Errorf("adding mirror signature to subtree %d: %d rows affected (want 1 row affected)", id, n)
	}
	return nil
}

func (i *Impl) GetCheckpointSubtree(ctx context.Context, mtcLogID string, id int64) (*CheckpointSubtreeModel, error) {
	var checkpointSubtree CheckpointSubtreeModel
	err := i.db.SelectOne(ctx, &checkpointSubtree,
		`SELECT id, mtcLogID, checkpointID, mtcaSignature,
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

// GetSubtreesForCheckpoint returns the subtrees of the checkpoint with the
// given ID, in order of their start.
func (i *Impl) GetSubtreesForCheckpoint(ctx context.Context, mtcLogID string, checkpointID int64) ([]*CheckpointSubtreeModel, error) {
	var subtrees []*CheckpointSubtreeModel
	_, err := i.db.Select(ctx, &subtrees,
		`SELECT id, mtcLogID, checkpointID, mtcaSignature,
				mirrorID, mirrorSignature,
				subtreeStart, subtreeEnd, subtreeHash
		 FROM checkpointSubtrees
		 WHERE mtcLogID = ? AND
		 	checkpointID = ?
		 ORDER BY subtreeStart`,
		mtcLogID,
		checkpointID)
	if err != nil {
		return nil, err
	}
	return subtrees, nil
}

// WithTransaction calls `github.com/letsencrypt/boulder/db.WithTransaction` for the given
// transaction function, with the built-in DB.
func (i *Impl) WithTransaction(ctx context.Context, f TxFunc) (any, error) {
	return db.WithTransaction(ctx, i.db, func(tx db.Executor) (any, error) {
		return f(txImpl{tx})
	})
}

// TxFunc is a function that gets run in a transaction by `Impl.WithTransaction` (or mocks).
type TxFunc func(tx Tx) (any, error)

// Tx represents a transaction.
//
// The methods on this are those that are currently called within a transaction by the MTCA.
// We don't include these methods on `*Impl` because we don't want them to be called outside
// a transaction. We don't include all the methods of `*Impl` here because any test that wants
// to mock `Impl.WithTransaction` needs to implement a `Tx`, which means such a test needs to
// implement each method in this interface. That means keeping it small is useful.
type Tx interface {
	AlreadyInitialized(ctx context.Context, mtcLogID string) (bool, error)
	InsertFirstCheckpoint(ctx context.Context, firstCheckpoint *CheckpointModel) error
	AddMTCASignature(ctx context.Context, id int64, caSig []byte, mtcLogID string) error
	SelectLatestForUpdate(ctx context.Context, mtcLogID string) (int64, error)
	SetLatestCheckpointID(ctx context.Context, mtcLogID string, old, new int64) error
	InsertCheckpointSubtree(ctx context.Context, subtree *CheckpointSubtreeModel) (int64, error)
}

type txImpl struct {
	tx db.Executor
}

// AlreadyInitialized returns true if the given mtcLogID is initialized already.
func (tx txImpl) AlreadyInitialized(ctx context.Context, mtcLogID string) (bool, error) {
	var numLatestCheckpoints int64
	err := tx.tx.SelectOne(ctx, &numLatestCheckpoints, "SELECT COUNT(*) FROM latestCheckpoint WHERE mtcLogID = ?",
		mtcLogID)
	if err != nil {
		return false, fmt.Errorf("getting latestCheckpoint: %s", err)
	}

	var numCheckpoints int64
	err = tx.tx.SelectOne(ctx, &numCheckpoints, "SELECT COUNT(*) FROM checkpoints WHERE mtcLogID = ?",
		mtcLogID)
	if err != nil {
		return false, fmt.Errorf("getting checkpoints: %s", err)
	}

	if numCheckpoints > 0 || numLatestCheckpoints > 0 {
		if numLatestCheckpoints == 1 {
			return true, nil
		}

		return false, fmt.Errorf("initializing issuance log for %s: already has %d checkpoints and %d latestCheckpoint rows",
			mtcLogID, numCheckpoints, numLatestCheckpoints)
	}

	return false, nil
}

// InsertFirstCheckpoint inserts a `CheckpointModel` and also inserts its ID into `latestCheckpoint` table.
func (tx txImpl) InsertFirstCheckpoint(ctx context.Context, firstCheckpoint *CheckpointModel) error {
	err := firstCheckpoint.Valid()
	if err != nil {
		return fmt.Errorf("first checkpoint invalid: %s", err)
	}
	if len(firstCheckpoint.MTCASignature) == 0 {
		return fmt.Errorf("first checkpoint needs MTCASignature")
	}

	err = tx.tx.Insert(ctx, firstCheckpoint)
	if err != nil {
		return err
	}

	_, err = tx.tx.ExecContext(ctx, "INSERT INTO latestCheckpoint (id, mtcLogID) VALUES (?, ?)", firstCheckpoint.ID, firstCheckpoint.MTCLogID)
	return err
}

// InsertCheckpointSubtree inserts a `CheckpointSubtreeModel` and returns the inserted row's ID.
func (tx txImpl) InsertCheckpointSubtree(ctx context.Context, subtree *CheckpointSubtreeModel) (int64, error) {
	err := subtree.Valid()
	if err != nil {
		return 0, fmt.Errorf("checkpoint subtree invalid: %s", err)
	}
	if subtree.CheckpointID == 0 {
		return 0, fmt.Errorf("checkpoint subtree needs CheckpointID")
	}
	if len(subtree.MTCASignature) == 0 {
		return 0, fmt.Errorf("checkpoint subtree needs MTCASignature")
	}

	err = tx.tx.Insert(ctx, subtree)
	if err != nil {
		return 0, fmt.Errorf("inserting into checkpointSubtrees table: %s", err)
	}
	return subtree.ID, nil
}

// AddMTCASignature updates an already-existing checkpoint to fill the MTCASignature field.
func (tx txImpl) AddMTCASignature(ctx context.Context, id int64, caSig []byte, mtcLogID string) error {
	result, err := tx.tx.ExecContext(ctx, "UPDATE checkpoints SET mtcaSignature = ? WHERE mtcLogID = ? AND id = ?",
		caSig, mtcLogID, id)
	if err != nil {
		return fmt.Errorf("updating checkpoint with MTCA signature: %s", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("updating checkpoint with MTCA signature, getting rows affected: %s", err)
	}
	if rowsAffected != 1 {
		return fmt.Errorf("updating checkpoint with MTCA signature: %d rows updated, want 1", rowsAffected)
	}
	return nil
}

// SelectLatestForUpdate does a `SELECT ... FOR UPDATE` of the `latestCheckpoint` row for the given mtcLogID, returning the row's ID.
func (tx txImpl) SelectLatestForUpdate(ctx context.Context, mtcLogID string) (int64, error) {
	// Lock the latestCheckpoint to make sure there is no concurrent signer/writer, avoiding signing a split view.
	// The FOR UPDATE does the heavy lifting here.
	// https://mariadb.com/docs/server/reference/sql-statements/data-manipulation/selecting-data/for-update
	var latestID int64
	err := tx.tx.SelectOne(ctx, &latestID,
		`SELECT id from latestCheckpoint WHERE mtcLogID = ? FOR UPDATE`,
		mtcLogID)
	if err != nil {
		return 0, err
	}
	return latestID, nil
}

// SetLatestCheckpointID updates the `latestCheckpoint` row for the given mtcLogID to point to the checkpoint with id `new`.
// Errors if the existing value in `latestCheckpoint was not equal to `old`.
func (tx txImpl) SetLatestCheckpointID(ctx context.Context, mtcLogID string, oldID, newID int64) error {
	result, err := tx.tx.ExecContext(ctx, "UPDATE latestCheckpoint SET id = ? WHERE mtcLogID = ? AND id = ?",
		newID, mtcLogID, oldID)
	if err != nil {
		return fmt.Errorf("updating latestCheckpoint: %s", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("updating latestCheckpoint, getting rows affected: %s", err)
	}
	if rowsAffected != 1 {
		return fmt.Errorf("updating latestCheckpoint: %d rows updated, rolling back", rowsAffected)
	}

	return nil
}
