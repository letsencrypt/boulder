package mtpublisher

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
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
	// cosigning mirrors have their cosignatures stored and their subtrees
	// signed.
	cosigning bool
	// completed is the ID of the last checkpoint a pass completed for this
	// mirror, which the next pass skips.
	completed int64
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
}

// New returns a publisher for the issuance log logID. It reconstructs each
// checkpoint's signed note from the stored MTCA signature, verified with
// caVerifier, and submits it to every mirror. It stores cosignatures from the
// cosigning mirrors only.
func New(checkpointDB checkpointDB, interval time.Duration, logID *issuancelog.ID, caVerifier *cosignature.Verifier, cosigning, submitOnly []Mirror, log blog.Logger) (*mtpublisher, error) {
	if interval <= 0 {
		return nil, fmt.Errorf("interval must be positive, got %s", interval)
	}
	if caVerifier == nil {
		return nil, errors.New("nil MTCA verifier")
	}
	if len(cosigning) == 0 {
		return nil, errors.New("no cosigning mirrors")
	}

	var publisherMirrors []*publisherMirror
	for _, mirror := range cosigning {
		publisherMirrors = append(publisherMirrors, &publisherMirror{Mirror: mirror, cosigning: true})
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
	GetUnsignedSubtrees(ctx context.Context, mtcLogID string, maxEnd int64, limit int) ([]*treedb.CheckpointSubtreeModel, error)
	AddSubtreeMirrorSignature(ctx context.Context, id int64, mirrorID string, mirrorSignature []byte, mtcLogID string) error
}

// publishCheckpoint submits the latest checkpoint to mirror and, if it is a
// cosigning mirror, stores the returned signature line. Start calls it at each
// interval.
func (p *mtpublisher) publishCheckpoint(ctx context.Context, mirror *publisherMirror) error {
	latest, err := p.treedb.LatestCheckpoint(ctx, p.logID.String())
	if errors.Is(err, treedb.ErrIssuanceLogNotInitialized) {
		p.log.Info(ctx, "Waiting for new checkpoint", blog.MTCLogID(p.logID.String()))
		return nil
	}
	if err != nil {
		return fmt.Errorf("selecting the latest checkpoint: %w", err)
	}
	if mirror.completed == latest.ID {
		return nil
	}

	if len(latest.RootHash) != tlog.HashSize {
		return fmt.Errorf("checkpoint %d root hash is %d bytes, want %d", latest.ID, len(latest.RootHash), tlog.HashSize)
	}

	// Assemble the checkpoint for submission to the mirror.
	tree := tlog.Tree{N: latest.TreeSize, Hash: tlog.Hash(latest.RootHash)}
	cp := &checkpoint.Checkpoint{Origin: p.logID.Origin(), Tree: tree}

	// Reconstruct the MTCA's cosignature line from the stored MTCA signature.
	if len(latest.MTCASignature) == 0 {
		return fmt.Errorf("checkpoint %d (%s size %d) has no MTCA signature", latest.ID, latest.MTCLogID, latest.TreeSize)
	}

	caCosignatureLine, err := cosignature.SignatureLine(p.caVerifier.Name(), p.caVerifier.KeyHash(), 0, latest.MTCASignature)
	if err != nil {
		return fmt.Errorf("checkpoint %d MTCA signature: %w", latest.ID, err)
	}

	// Reconstruct the signed note for submission to the mirror, and verify
	// the MTCA signature before submitting it.
	signedNoteForMirror, err := cp.SignedNote(caCosignatureLine)
	if err != nil {
		return fmt.Errorf("assembling checkpoint %d signed note: %w", latest.ID, err)
	}
	_, _, err = checkpoint.Open(signedNoteForMirror, p.caVerifier)
	if err != nil {
		return fmt.Errorf("checkpoint %d MTCA signature: %w", latest.ID, err)
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
	if !mirror.cosigning {
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

// subtreeBatch is the number of unsigned subtrees cosignSubtrees takes per
// pass. The mirror's checkpoint bounds the query, so every subtree taken is
// one the mirror can sign, and the batch only bounds the work of one pass.
const subtreeBatch = 100

// cosignSubtrees stores mirror's signature on each unsigned subtree that its
// checkpoint includes, newest first, up to subtreeBatch per pass. Start calls
// it at each interval.
func (p *mtpublisher) cosignSubtrees(ctx context.Context, mirror *publisherMirror) error {
	mirrored, mirrorLine, err := mirror.LatestCheckpoint(ctx, p.logID.Origin())
	if err != nil {
		return fmt.Errorf("fetching the mirror's checkpoint of %s: %w", p.logID, err)
	}
	subtrees, err := p.treedb.GetUnsignedSubtrees(ctx, p.logID.String(), mirrored.Tree.N, subtreeBatch)
	if err != nil {
		return fmt.Errorf("selecting the unsigned subtrees of %s: %w", p.logID, err)
	}
	for _, subtree := range subtrees {
		if len(subtree.MTCASignature) == 0 {
			return fmt.Errorf("subtree %d (%s [%d, %d)) has no MTCA signature", subtree.ID, subtree.MTCLogID, subtree.SubtreeStart, subtree.SubtreeEnd)
		}
		err = subtree.Valid()
		if err != nil {
			return fmt.Errorf("compliance problem: the MTCA signed an invalid subtree %d (%s [%d, %d)): %s", subtree.ID, subtree.MTCLogID, subtree.SubtreeStart, subtree.SubtreeEnd, err)
		}
		start := subtree.SubtreeStart
		end := subtree.SubtreeEnd
		subtreeHash := tlog.Hash(subtree.SubtreeHash)
		if !p.caVerifier.VerifySubtreeSignature(p.logID.Origin(), start, end, subtreeHash, subtree.MTCASignature) {
			return fmt.Errorf("subtree %d (%s [%d, %d)) MTCA signature does not verify", subtree.ID, subtree.MTCLogID, subtree.SubtreeStart, subtree.SubtreeEnd)
		}

		subtreeSignature, err := mirror.CosignSubtree(ctx, mirrored, mirrorLine, start, end, subtreeHash)
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

// Start runs publishCheckpoint for each mirror and cosignSubtrees for each
// cosigning mirror at each interval, each concurrently, until ctx is
// cancelled.
func (p *mtpublisher) Start(ctx context.Context) {
	var wg sync.WaitGroup
	for _, mirror := range p.mirrors {
		wg.Go(func() { p.run(ctx, mirror, "Publishing checkpoint", p.publishCheckpoint) })
		if mirror.cosigning {
			wg.Go(func() { p.run(ctx, mirror, "Cosigning subtrees", p.cosignSubtrees) })
		}
	}
	wg.Wait()
}

// run calls operationFunc on mirror at each interval until ctx is cancelled.
// It logs each error with the operation and the mirror's ID.
func (p *mtpublisher) run(ctx context.Context, mirror *publisherMirror, operation string, operationFunc func(context.Context, *publisherMirror) error) {
	ctx = blog.ContextWith(ctx, slog.String("mirrorID", mirror.ID()))
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		// Check for context cancellation before doing any work, in case the
		// last pass overran the tick and both cases were selectable at once.
		if ctx.Err() != nil {
			return
		}
		err := operationFunc(ctx, mirror)
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
