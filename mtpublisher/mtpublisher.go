package mtpublisher

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/blog"
	"github.com/letsencrypt/boulder/trees/checkpoint"
	"github.com/letsencrypt/boulder/trees/cosignature"
	"github.com/letsencrypt/boulder/trees/issuancelog"
	"github.com/letsencrypt/boulder/trees/treedb"
)

// Mirror cosigns checkpoints, requiring the entries they commit to before
// signing.
//
// https://c2sp.org/tlog-cosignature
type Mirror interface {
	// ID returns the mirror's cosigner ID.
	ID() string
	// SubmitCheckpoint submits the log's signed note for cp and returns the
	// mirror's cosignature line, verified against the mirror's key.
	SubmitCheckpoint(ctx context.Context, cp *checkpoint.Checkpoint, signedNote []byte) ([]byte, error)
	// LatestCheckpoint returns the mirror's checkpoint of the log with origin
	// and the mirror's cosignature line on it, verified against the mirror's
	// key. The mirror signs the subtrees the checkpoint includes.
	LatestCheckpoint(ctx context.Context, origin string) (*checkpoint.Checkpoint, []byte, error)
	// CosignSubtree returns the mirror's signature over the subtree [start,
	// end) of mirrored, the mirror's checkpoint from LatestCheckpoint,
	// verified against the mirror's key. It errors if the mirror's checkpoint
	// does not include the subtree.
	CosignSubtree(ctx context.Context, mirrored *checkpoint.Checkpoint, mirrorLine []byte, start, end int64, subtreeHash tlog.Hash) ([]byte, error)
}

// publisherMirror is a mirror the publisher submits to.
type publisherMirror struct {
	Mirror
	// cosigner mirrors have their cosignatures stored and their subtrees
	// signed.
	cosigner bool
	// completed is the ID of the last checkpoint a pass completed for this
	// mirror, which the next pass skips.
	completed int64
	// submitting is set while a goroutine is submitting to this mirror.
	submitting atomic.Bool
	// signing is set while a goroutine is having this mirror sign subtrees.
	signing atomic.Bool
}

// mtpublisher obtains and stores its mirrors' cosignatures over the issuance
// log's latest checkpoint and the log's subtrees.
type mtpublisher struct {
	treedb     checkpointDB
	interval   time.Duration
	logID      *issuancelog.ID
	mirrors    []*publisherMirror
	caVerifier *cosignature.Verifier
	log        blog.Logger
	wg         sync.WaitGroup
}

// New returns a publisher for the issuance log logID. It reconstructs each
// checkpoint's signed note from the stored MTCA signature, verified with
// caVerifier, and submits it to every mirror. It stores cosignatures from the
// cosigner mirrors only.
func New(checkpointDB checkpointDB, interval time.Duration, logID *issuancelog.ID, caVerifier *cosignature.Verifier, cosigners, submitOnly []Mirror, log blog.Logger) (*mtpublisher, error) {
	if interval <= 0 {
		return nil, fmt.Errorf("interval must be positive, got %s", interval)
	}
	if caVerifier == nil {
		return nil, errors.New("nil MTCA verifier")
	}
	if len(cosigners) == 0 {
		return nil, errors.New("no cosigner mirrors")
	}

	var publisherMirrors []*publisherMirror
	for _, mirror := range cosigners {
		publisherMirrors = append(publisherMirrors, &publisherMirror{Mirror: mirror, cosigner: true})
	}
	for _, mirror := range submitOnly {
		publisherMirrors = append(publisherMirrors, &publisherMirror{Mirror: mirror})
	}

	return &mtpublisher{
		treedb:     checkpointDB,
		interval:   interval,
		logID:      logID,
		mirrors:    publisherMirrors,
		caVerifier: caVerifier,
		log:        log,
	}, nil
}

// checkpointDB is the subset of treedb.Impl the publisher uses, so tests can
// substitute their own.
type checkpointDB interface {
	LatestCheckpoint(ctx context.Context, mtcLogID string) (*treedb.CheckpointModel, error)
	AddMirrorSignature(ctx context.Context, id int64, mirrorID string, mirrorSignature []byte, mtcLogID string) error
	GetUnsignedSubtrees(ctx context.Context, mtcLogID string, limit int) ([]*treedb.SubtreeModel, error)
	AddSubtreeMirrorSignature(ctx context.Context, id int64, mirrorID string, mirrorSignature []byte, mtcLogID string) error
}

// startIfIdle runs operationFunc for mirror in its own goroutine, unless busy
// says the one an earlier pass started is still running. It logs each error
// with the operation and the mirror's ID.
func (p *mtpublisher) startIfIdle(ctx context.Context, mirror *publisherMirror, busy *atomic.Bool, operation string, operationFunc func(context.Context) error) {
	if !busy.CompareAndSwap(false, true) {
		return
	}
	p.wg.Go(func() {
		defer busy.Store(false)
		ctx := blog.ContextWith(ctx, slog.String("mirrorID", mirror.ID()))
		err := operationFunc(ctx)
		if err != nil {
			p.log.Error(ctx, "Publish failed", err, slog.String("operation", operation))
		}
	})
}

// submitCheckpoint submits the latest checkpoint to mirror and, if it is a
// cosigner mirror, stores the returned signature line.
func (p *mtpublisher) submitCheckpoint(ctx context.Context, mirror *publisherMirror, latest *treedb.CheckpointModel, cp *checkpoint.Checkpoint, signedNoteForMirror []byte) error {
	if mirror.completed == latest.ID {
		return nil
	}

	// Submit the signed checkpoint to the mirror for cosigning.
	checkpointCosignatureLine, err := mirror.SubmitCheckpoint(ctx, cp, signedNoteForMirror)
	if err != nil {
		return fmt.Errorf("publishing checkpoint %d (%s size %d): %w", latest.ID, latest.MTCLogID, latest.TreeSize, err)
	}
	p.log.Info(ctx, "Published checkpoint to mirror",
		blog.MTCLogID(latest.MTCLogID),
		slog.Int64("id", latest.ID),
		slog.Int64("treesize", latest.TreeSize),
	)
	if !mirror.cosigner {
		mirror.completed = latest.ID
		return nil
	}

	// Store the mirror's cosignature in the database.
	err = p.treedb.AddMirrorSignature(ctx, latest.ID, mirror.ID(), checkpointCosignatureLine, p.logID.String())
	if errors.Is(err, treedb.ErrAlreadyCosigned) {
		p.log.Info(ctx, "Checkpoint already has a cosignature from another mirror",
			blog.MTCLogID(latest.MTCLogID),
			slog.Int64("id", latest.ID),
			slog.Int64("treesize", latest.TreeSize),
		)
		mirror.completed = latest.ID
		return nil
	}
	if err != nil {
		return fmt.Errorf("storing checkpoint %d cosignature (%s size %d): %w", latest.ID, latest.MTCLogID, latest.TreeSize, err)
	}
	p.log.Info(ctx, "Stored checkpoint cosignature from mirror",
		blog.MTCLogID(latest.MTCLogID),
		slog.Int64("id", latest.ID),
		slog.Int64("treesize", latest.TreeSize),
	)
	mirror.completed = latest.ID
	return nil
}

// publishCheckpoint reads the latest checkpoint and starts submitCheckpoint
// for each idle mirror. Start calls it at each interval.
//
// Builds a checkpoint signed note to send the mirror based on the contents of
// the latest checkpoint in the DB.
func (p *mtpublisher) publishCheckpoint(ctx context.Context) error {
	latest, err := p.treedb.LatestCheckpoint(ctx, p.logID.String())
	if errors.Is(err, treedb.ErrIssuanceLogNotInitialized) {
		p.log.Info(ctx, "Waiting for new checkpoint", blog.MTCLogID(p.logID.String()))
		return nil
	}
	if err != nil {
		return fmt.Errorf("selecting the latest checkpoint: %w", err)
	}

	if len(latest.RootHash) != tlog.HashSize {
		return fmt.Errorf("checkpoint %d root hash is %d bytes, want %d", latest.ID, len(latest.RootHash), tlog.HashSize)
	}

	// Assemble the checkpoint for submission to the mirrors.
	tree := tlog.Tree{N: latest.TreeSize, Hash: tlog.Hash(latest.RootHash)}
	cp := &checkpoint.Checkpoint{Origin: p.logID.Origin(), Tree: tree}

	if len(latest.MTCASignature) == 0 {
		return fmt.Errorf("checkpoint %d (%s size %d) has no MTCA signature", latest.ID, latest.MTCLogID, latest.TreeSize)
	}

	// Reconstruct the signed note for submission to the mirrors, and verify
	// the MTCA signature before submitting it.
	signedNoteForMirror, err := cp.SignedNote(latest.MTCASignature)
	if err != nil {
		return fmt.Errorf("assembling checkpoint %d signed note: %w", latest.ID, err)
	}
	_, _, err = checkpoint.Open(signedNoteForMirror, p.caVerifier)
	if err != nil {
		return fmt.Errorf("checkpoint %d MTCA signature: %w", latest.ID, err)
	}

	for _, mirror := range p.mirrors {
		p.startIfIdle(ctx, mirror, &mirror.submitting, "Publishing checkpoint", func(ctx context.Context) error {
			return p.submitCheckpoint(ctx, mirror, latest, cp, signedNoteForMirror)
		})
	}
	return nil
}

// subtreeBatch is the number of unsigned subtrees cosignSubtrees takes per
// pass. Each mirror signs the ones its checkpoint includes, and the batch only
// bounds the work of one pass.
const subtreeBatch = 100

// signSubtrees stores mirror's signature on each of subtrees that its
// checkpoint includes.
func (p *mtpublisher) signSubtrees(ctx context.Context, mirror *publisherMirror, subtrees []*treedb.SubtreeModel) error {
	mirrored, mirrorLine, err := mirror.LatestCheckpoint(ctx, p.logID.Origin())
	if err != nil {
		return fmt.Errorf("fetching the mirror's checkpoint of %s: %w", p.logID, err)
	}
	for _, subtree := range subtrees {
		if subtree.SubtreeEnd > mirrored.Tree.N {
			continue
		}

		subtreeSignature, err := mirror.CosignSubtree(ctx, mirrored, mirrorLine, subtree.SubtreeStart, subtree.SubtreeEnd, tlog.Hash(subtree.SubtreeHash))
		if err != nil {
			return fmt.Errorf("cosigning subtree %d (%s [%d, %d)): %w", subtree.ID, subtree.MTCLogID, subtree.SubtreeStart, subtree.SubtreeEnd, err)
		}
		err = p.treedb.AddSubtreeMirrorSignature(ctx, subtree.ID, mirror.ID(), subtreeSignature, p.logID.String())
		if errors.Is(err, treedb.ErrAlreadyCosigned) {
			p.log.Info(ctx, "Subtree already has a signature from another mirror",
				blog.MTCLogID(subtree.MTCLogID),
				slog.Group("subtree",
					slog.Int64("id", subtree.ID),
					slog.Int64("start", subtree.SubtreeStart),
					slog.Int64("end", subtree.SubtreeEnd)),
			)
			continue
		}
		if err != nil {
			return fmt.Errorf("storing subtree %d cosignature (%s [%d, %d)): %w", subtree.ID, subtree.MTCLogID, subtree.SubtreeStart, subtree.SubtreeEnd, err)
		}
		p.log.Info(ctx, "Stored mirror signature for subtree",
			blog.MTCLogID(subtree.MTCLogID),
			slog.Group("subtree",
				slog.Int64("id", subtree.ID),
				slog.Int64("start", subtree.SubtreeStart),
				slog.Int64("end", subtree.SubtreeEnd)),
		)
	}
	return nil
}

// cosignSubtrees reads the unsigned subtrees, newest first, up to subtreeBatch
// per pass, and starts signSubtrees for each idle cosigner mirror. Start calls
// it at each interval.
func (p *mtpublisher) cosignSubtrees(ctx context.Context) error {
	subtrees, err := p.treedb.GetUnsignedSubtrees(ctx, p.logID.String(), subtreeBatch)
	if err != nil {
		return fmt.Errorf("selecting the unsigned subtrees of %s: %w", p.logID, err)
	}
	if len(subtrees) == 0 {
		return nil
	}
	for _, subtree := range subtrees {
		if len(subtree.MTCASignature) == 0 {
			return fmt.Errorf("subtree %d (%s [%d, %d)) has no MTCA signature", subtree.ID, subtree.MTCLogID, subtree.SubtreeStart, subtree.SubtreeEnd)
		}
		err = subtree.Valid()
		if err != nil {
			return fmt.Errorf("compliance problem: the MTCA signed an invalid subtree %d (%s [%d, %d)): %s", subtree.ID, subtree.MTCLogID, subtree.SubtreeStart, subtree.SubtreeEnd, err)
		}
		if !p.caVerifier.VerifySubtreeSignature(p.logID.Origin(), subtree.SubtreeStart, subtree.SubtreeEnd, tlog.Hash(subtree.SubtreeHash), subtree.MTCASignature) {
			return fmt.Errorf("subtree %d (%s [%d, %d)) MTCA signature does not verify", subtree.ID, subtree.MTCLogID, subtree.SubtreeStart, subtree.SubtreeEnd)
		}
	}

	for _, mirror := range p.mirrors {
		if !mirror.cosigner {
			continue
		}
		p.startIfIdle(ctx, mirror, &mirror.signing, "Cosigning subtrees", func(ctx context.Context) error {
			return p.signSubtrees(ctx, mirror, subtrees)
		})
	}
	return nil
}

// run calls operationFunc at each interval until ctx is cancelled. It logs
// each error with the operation.
func (p *mtpublisher) run(ctx context.Context, operation string, operationFunc func(context.Context) error) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		// Check for context cancellation before doing any work, in case the
		// last pass overran the tick and both cases were selectable at once.
		if ctx.Err() != nil {
			return
		}
		err := operationFunc(ctx)
		if err != nil {
			p.log.Error(ctx, "Publish failed", err, slog.String("operation", operation))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Start runs publishCheckpoint and cosignSubtrees at each interval, each
// concurrently, until ctx is cancelled.
func (p *mtpublisher) Start(ctx context.Context) {
	p.wg.Go(func() { p.run(ctx, "Publishing checkpoint", p.publishCheckpoint) })
	p.wg.Go(func() { p.run(ctx, "Cosigning subtrees", p.cosignSubtrees) })
	p.wg.Wait()
}
