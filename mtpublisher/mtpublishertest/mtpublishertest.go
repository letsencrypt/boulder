//go:build go1.27

// Package mtpublishertest provides an in-process cosigner for unit tests of the
// mtca and the mtpublisher.
package mtpublishertest

import (
	"context"
	"crypto"
	"fmt"

	"github.com/letsencrypt/boulder/trees/checkpoint"
	"github.com/letsencrypt/boulder/trees/cosignature"
)

// TestMirror is a mtpublisher.Mirror that cosigns in process with its own key,
// without checking that the checkpoint's entries exist anywhere.
type TestMirror struct {
	cosignerID string
	cosigner   *cosignature.Cosigner
}

// NewTestMirror returns a TestMirror that cosigns checkpoints of the log with
// the given origin as the cosigner with ID mirrorID.
func NewTestMirror(mirrorID, origin string, signer crypto.Signer) (*TestMirror, error) {
	cosigner, err := cosignature.NewCosigner(mirrorID, origin, signer)
	if err != nil {
		return nil, fmt.Errorf("creating mirror cosigner: %s", err)
	}
	return &TestMirror{cosignerID: mirrorID, cosigner: cosigner}, nil
}

// ID returns the mirror's cosigner ID.
func (m *TestMirror) ID() string {
	return m.cosignerID
}

// Cosign cosigns the checkpoint and returns the raw cosignature. It errors if
// the checkpoint is not of the cosigner's log.
func (m *TestMirror) Cosign(_ context.Context, cp *checkpoint.Checkpoint, _ []byte) ([]byte, error) {
	if cp.Origin != m.cosigner.Origin() {
		return nil, fmt.Errorf("checkpoint origin %q is not this mirror's log %q", cp.Origin, m.cosigner.Origin())
	}
	timestampedCosignature, err := m.cosigner.CosignCheckpoint(cp.Tree)
	if err != nil {
		return nil, err
	}
	return cosignature.RawSignature(timestampedCosignature)
}
