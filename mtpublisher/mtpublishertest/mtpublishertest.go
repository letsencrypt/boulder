// Package mtpublishertest provides an in-process cosigner for unit tests of the
// mtca and the mtpublisher.
package mtpublishertest

import (
	"context"
	"crypto"
	"crypto/mldsa"
	"fmt"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/trees/checkpoint"
	"github.com/letsencrypt/boulder/trees/cosignature"
)

// TestMirror is a mtpublisher.Mirror that cosigns in process with its own key,
// without checking that the checkpoint's entries exist anywhere.
type TestMirror struct {
	cosignerID string
	cosigner   *cosignature.Cosigner
	verifier   *cosignature.Verifier
	// latest is the last checkpoint the mirror cosigned and latestLine its
	// cosignature line, which it serves.
	latest     *checkpoint.Checkpoint
	latestLine []byte
}

// NewTestMirror returns a TestMirror that cosigns checkpoints of the log with
// the given origin as the cosigner with ID mirrorID.
func NewTestMirror(mirrorID, origin string, signer crypto.Signer) (*TestMirror, error) {
	cosigner, err := cosignature.NewCosigner(mirrorID, origin, signer)
	if err != nil {
		return nil, fmt.Errorf("creating mirror cosigner: %s", err)
	}
	publicKey, ok := signer.Public().(*mldsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("mirror public key is %T, must be ML-DSA-44", signer.Public())
	}
	verifier, err := cosignature.NewVerifier(mirrorID, publicKey)
	if err != nil {
		return nil, fmt.Errorf("creating mirror verifier: %s", err)
	}
	return &TestMirror{cosignerID: mirrorID, cosigner: cosigner, verifier: verifier}, nil
}

// ID returns the mirror's cosigner ID.
func (m *TestMirror) ID() string {
	return m.cosignerID
}

// SubmitCheckpoint cosigns the checkpoint, serves it as the latest, and returns
// the cosignature line. It errors if the checkpoint is not of the cosigner's
// log.
func (m *TestMirror) SubmitCheckpoint(_ context.Context, cp *checkpoint.Checkpoint, _ []byte) ([]byte, error) {
	if cp.Origin != m.cosigner.Origin() {
		return nil, fmt.Errorf("checkpoint origin %q is not this mirror's log %q", cp.Origin, m.cosigner.Origin())
	}
	timestampedCosignature, err := m.cosigner.CosignCheckpoint(cp.Tree)
	if err != nil {
		return nil, err
	}
	rawCosignature, err := cosignature.RawSignature(timestampedCosignature)
	if err != nil {
		return nil, err
	}
	line, err := cosignature.SignatureLine(m.verifier.Name(), m.verifier.KeyHash(), 0, rawCosignature)
	if err != nil {
		return nil, err
	}
	m.latest = cp
	m.latestLine = line
	return line, nil
}

// LatestCheckpoint returns the last checkpoint the mirror cosigned and its
// cosignature line. It errors if origin is not the cosigner's log or no
// checkpoint was submitted yet.
func (m *TestMirror) LatestCheckpoint(_ context.Context, origin string) (*checkpoint.Checkpoint, []byte, error) {
	if origin != m.cosigner.Origin() {
		return nil, nil, fmt.Errorf("origin %q is not this mirror's log %q", origin, m.cosigner.Origin())
	}
	if m.latest == nil {
		return nil, nil, fmt.Errorf("no checkpoint of %q was submitted yet", origin)
	}
	return m.latest, m.latestLine, nil
}

// CosignSubtree returns the mirror's signature over the subtree [start, end).
// It errors if origin is not the cosigner's log or the last checkpoint the
// mirror cosigned does not include the subtree.
func (m *TestMirror) CosignSubtree(ctx context.Context, origin string, start, end int64, subtreeHash tlog.Hash) ([]byte, error) {
	latest, _, err := m.LatestCheckpoint(ctx, origin)
	if err != nil {
		return nil, err
	}
	if latest.Tree.N < end {
		return nil, fmt.Errorf("mirror checkpoint at size %d does not include subtree [%d, %d)", latest.Tree.N, start, end)
	}
	return m.cosigner.CosignSubtree(start, end, subtreeHash)
}
