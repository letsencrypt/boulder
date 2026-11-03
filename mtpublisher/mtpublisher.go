package mtpublisher

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	blog "github.com/letsencrypt/boulder/log"
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

// mtpublisher obtains and stores its mirror's cosignatures over the issuance
// log's latest checkpoint and the log's subtrees.
type mtpublisher struct {
	treedb     checkpointDB
	interval   time.Duration
	logID      *issuancelog.ID
	mirror     Mirror
	caVerifier *cosignature.Verifier
	log        blog.Logger
}

// New returns a publisher for the issuance log logID. It reconstructs each
// checkpoint's signed note from the stored MTCA signature, verified with
// caVerifier, and obtains each cosignature from mirror, which verifies it
// before returning it.
func New(checkpointDB checkpointDB, interval time.Duration, logID *issuancelog.ID, caVerifier *cosignature.Verifier, mirror Mirror, log blog.Logger) (*mtpublisher, error) {
	if interval <= 0 {
		return nil, fmt.Errorf("interval must be positive, got %s", interval)
	}
	if caVerifier == nil {
		return nil, errors.New("nil MTCA verifier")
	}

	return &mtpublisher{
		treedb:     checkpointDB,
		interval:   interval,
		logID:      logID,
		mirror:     mirror,
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

// PublishCheckpoint submits the latest checkpoint to the mirror if it lacks a
// mirror cosignature and stores the returned signature line. Start calls it at
// each interval.
func (p *mtpublisher) PublishCheckpoint(ctx context.Context) error {
	latest, err := p.treedb.LatestCheckpoint(ctx, p.logID.String())
	if errors.Is(err, treedb.ErrIssuanceLogNotInitialized) {
		p.log.Infof("Issuance log %s has no checkpoint yet, waiting", p.logID)
		return nil
	}
	if err != nil {
		return fmt.Errorf("selecting the latest checkpoint: %w", err)
	}
	if len(latest.MirrorSignature) > 0 {
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
	checkpointCosignatureLine, err := p.mirror.SubmitCheckpoint(ctx, cp, signedNoteForMirror)
	if err != nil {
		return fmt.Errorf("publishing checkpoint %d (%s size %d): %w", latest.ID, latest.MTCLogID, latest.TreeSize, err)
	}
	p.log.Infof("Published checkpoint %d (%s size %d)", latest.ID, latest.MTCLogID, latest.TreeSize)

	// Store the mirror's cosignature in the database.
	err = p.treedb.AddMirrorSignature(ctx, latest.ID, p.mirror.ID(), checkpointCosignatureLine, p.logID.String())
	if err != nil {
		return fmt.Errorf("storing checkpoint %d cosignature (%s size %d): %w", latest.ID, latest.MTCLogID, latest.TreeSize, err)
	}
	p.log.Infof("Stored mirror cosignature for checkpoint %d (%s size %d)", latest.ID, latest.MTCLogID, latest.TreeSize)
	return nil
}

// subtreeBatch is the number of unsigned subtrees CosignSubtrees takes per
// pass. The mirror's checkpoint bounds the query, so every subtree taken is
// one the mirror can sign, and the batch only bounds the work of one pass.
const subtreeBatch = 100

// CosignSubtrees stores the mirror's signature on each of the log's subtrees
// that lack one and that the mirror's checkpoint includes, newest first, up to
// subtreeBatch per pass. Start calls it at each interval.
func (p *mtpublisher) CosignSubtrees(ctx context.Context) error {
	mirrored, mirrorLine, err := p.mirror.LatestCheckpoint(ctx, p.logID.Origin())
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

		subtreeSignature, err := p.mirror.CosignSubtree(ctx, mirrored, mirrorLine, start, end, subtreeHash)
		if err != nil {
			return fmt.Errorf("cosigning subtree %d (%s [%d, %d)): %w", subtree.ID, subtree.MTCLogID, subtree.SubtreeStart, subtree.SubtreeEnd, err)
		}
		err = p.treedb.AddSubtreeMirrorSignature(ctx, subtree.ID, p.mirror.ID(), subtreeSignature, p.logID.String())
		if err != nil {
			return fmt.Errorf("storing subtree %d cosignature (%s [%d, %d)): %w", subtree.ID, subtree.MTCLogID, subtree.SubtreeStart, subtree.SubtreeEnd, err)
		}
		p.log.Infof("Stored mirror signature for subtree %d (%s [%d, %d))", subtree.ID, subtree.MTCLogID, subtree.SubtreeStart, subtree.SubtreeEnd)
	}
	return nil
}

// Start runs PublishCheckpoint and CosignSubtrees at each interval, each in
// its own goroutine so that neither waits on the other, until ctx is
// cancelled.
func (p *mtpublisher) Start(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Go(func() { p.run(ctx, "Publishing checkpoint", p.PublishCheckpoint) })
	wg.Go(func() { p.run(ctx, "Cosigning subtrees", p.CosignSubtrees) })
	wg.Wait()
}

// run calls operationFunc at each interval until ctx is cancelled, logging its
// errors under operation.
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
			p.log.Errf("%s failed: %s", operation, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
