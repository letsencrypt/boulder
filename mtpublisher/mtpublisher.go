package mtpublisher

import (
	"context"
	"crypto/mldsa"
	"errors"
	"fmt"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/trees/checkpoint"
	"github.com/letsencrypt/boulder/trees/cosignature"
	"github.com/letsencrypt/boulder/trees/issuancelog"
	"github.com/letsencrypt/boulder/trees/treedb"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type mtpublisherMetrics struct {
	cosignDuration          prometheus.Histogram
	entriesUploaded         *prometheus.CounterVec
	lastPubSuccessTimestamp prometheus.Gauge
	mirrorRequestDuration   *prometheus.HistogramVec
	publishPasses           *prometheus.CounterVec
	sourceDurations         *prometheus.HistogramVec
	treeSize                *prometheus.GaugeVec
	verifyFailures          *prometheus.CounterVec
}

func NewMTPublisherMetrics(register prometheus.Registerer) *mtpublisherMetrics {
	cosignDuration := promauto.With(register).NewHistogram(prometheus.HistogramOpts{
		Name: "mtpub_cosign_duration_seconds",
		Help: "Duration of cosign operation in seconds",
	})
	entriesUploaded := promauto.With(register).NewCounterVec(prometheus.CounterOpts{
		Name: "mtpub_entries_uploaded_total",
		Help: "Total count of entries uploaded by result",
	}, []string{"result"})
	lastPubSuccessTimestamp := promauto.With(register).NewGauge(prometheus.GaugeOpts{
		Name: "mtpub_last_publish_success_timestamp_seconds",
		Help: "Timestamp of last publish pass success",
	})
	mirrorRequestDuration := promauto.With(register).NewHistogramVec(prometheus.HistogramOpts{
		Name: "mtpub_mirror_request_duration_seconds",
		Help: "Observations of duration for mirror requests in seconds",
	}, []string{"mirror", "endpoint", "status"})
	publishPasses := promauto.With(register).NewCounterVec(prometheus.CounterOpts{
		Name: "mtpub_publish_passes_total",
		Help: "Total count of publish passes by result",
	}, []string{"result"})
	sourceDurations := promauto.With(register).NewHistogramVec(prometheus.HistogramOpts{
		Name: "mtpub_source_duration_seconds",
		Help: "Source durations by operation",
	}, []string{"operation"})
	treeSize := promauto.With(register).NewGaugeVec(prometheus.GaugeOpts{
		Name: "mtpub_tree_size",
		Help: "Gauge of tree size by type, latest or mirrored",
	}, []string{"type"})
	verifyFailures := promauto.With(register).NewCounterVec(prometheus.CounterOpts{
		Name: "mtpub_sig_verify_failures_total",
		Help: "Total count of signature verification failures by signer",
	}, []string{"signer"})

	return &mtpublisherMetrics{
		cosignDuration,
		entriesUploaded,
		lastPubSuccessTimestamp,
		mirrorRequestDuration,
		publishPasses,
		sourceDurations,
		treeSize,
		verifyFailures,
	}
}

// Mirror cosigns checkpoints, requiring the entries they commit to before
// signing.
//
// https://c2sp.org/tlog-cosignature
type Mirror interface {
	// ID returns the mirror's cosigner ID.
	ID() string
	// Cosign submits the log's signed note for cp and returns the mirror's raw
	// cosignature, verified against the mirror's key.
	Cosign(ctx context.Context, cp *checkpoint.Checkpoint, signedNote []byte) ([]byte, error)
}

// mtpublisher obtains and stores its mirror's cosignature over the issuance
// log's latest checkpoint.
type mtpublisher struct {
	treedb     checkpointDB
	interval   time.Duration
	logID      issuancelog.ID
	mirror     Mirror
	caVerifier *cosignature.Verifier
	log        blog.Logger
	metrics    *mtpublisherMetrics
}

// New returns a publisher for the issuance log logID. It reconstructs each
// checkpoint's signed note from the stored MTCA signature, verified against
// mtcaPublicKey, and obtains each cosignature from mirror, which verifies it
// before returning it.
func New(checkpointDB checkpointDB, interval time.Duration, logID issuancelog.ID, mtcaPublicKey *mldsa.PublicKey, mirror Mirror, log blog.Logger, metrics *mtpublisherMetrics) (*mtpublisher, error) {
	if interval <= 0 {
		return nil, fmt.Errorf("interval must be positive, got %s", interval)
	}

	caVerifier, err := cosignature.NewVerifier(logID.CAID, mtcaPublicKey)
	if err != nil {
		return nil, fmt.Errorf("creating MTCA verifier: %s", err)
	}

	return &mtpublisher{
		treedb:     checkpointDB,
		interval:   interval,
		logID:      logID,
		mirror:     mirror,
		caVerifier: caVerifier,
		log:        log,
		metrics:    metrics,
	}, nil
}

// checkpointDB is the subset of treedb.Impl the publisher uses, so tests can
// substitute their own.
type checkpointDB interface {
	LatestCheckpoint(ctx context.Context, mtcLogID string) (*treedb.CheckpointModel, error)
	AddMirrorSignature(ctx context.Context, id int64, mirrorID string, mirrorSignature []byte, mtcLogID string) error
}

// Publish submits the latest checkpoint to the mirror if it lacks a mirror
// cosignature and stores the returned raw cosignature. Start calls it at each
// interval.
func (p *mtpublisher) Publish(ctx context.Context) (err error) {
	defer func() {
		// This func closes over the named value `err`, so can reference it
		result := "success"
		if err != nil {
			result = "failed"
		}
		p.metrics.publishPasses.With(prometheus.Labels{"result": result}).Inc()
	}()
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

	observationStart := time.Now()
	// Submit the signed checkpoint to the mirror for cosigning.
	mirrorRawCosig, err := p.mirror.Cosign(ctx, cp, signedNoteForMirror)
	observationDuration := time.Since(observationStart).Seconds()
	if err != nil {
		p.metrics.cosignDuration.Observe(observationDuration)
		return fmt.Errorf("publishing checkpoint %d (%s size %d): %w", latest.ID, latest.MTCLogID, latest.TreeSize, err)
	}
	p.metrics.cosignDuration.Observe(observationDuration)
	p.log.Infof("Published checkpoint %d (%s size %d)", latest.ID, latest.MTCLogID, latest.TreeSize)

	// Store the mirror's cosignature in the database.
	err = p.treedb.AddMirrorSignature(ctx, latest.ID, p.mirror.ID(), mirrorRawCosig, p.logID.String())
	if err != nil {
		return fmt.Errorf("storing checkpoint %d cosignature (%s size %d): %w", latest.ID, latest.MTCLogID, latest.TreeSize, err)
	}
	p.log.Infof("Stored mirror cosignature for checkpoint %d (%s size %d)", latest.ID, latest.MTCLogID, latest.TreeSize)
	return nil
}

// Start attempts to publish the latest checkpoint at each interval until ctx is
// cancelled.
func (p *mtpublisher) Start(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		err := p.Publish(ctx)
		if err != nil {
			p.log.Errf("Publishing pass failed: %s", err)
		} else {
			p.metrics.lastPubSuccessTimestamp.SetToCurrentTime()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
