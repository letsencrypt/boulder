// Package mtpublishertest provides an in-process cosigner for unit tests of the
// mtca and the mtpublisher.
package mtpublishertest

import (
	"context"
	"crypto"
	"crypto/mldsa"
	"fmt"

	"github.com/letsencrypt/boulder/trees/checkpoint"
	"github.com/letsencrypt/boulder/trees/cosignature"
	"github.com/letsencrypt/boulder/trees/cosigned"
)

// Timestamp is the timestamp the TestMirror puts in its checkpoint
// cosignatures.
const Timestamp uint64 = 1_700_000_000

// TestMirror is a mtpublisher.Mirror that cosigns in process with its own key,
// without checking that the checkpoint's entries exist anywhere.
type TestMirror struct {
	cosignerID string
	signer     crypto.Signer
	cosigner   *cosignature.Cosigner
	verifier   *cosignature.Verifier
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
	return &TestMirror{cosignerID: mirrorID, signer: signer, cosigner: cosigner, verifier: verifier}, nil
}

// ID returns the mirror's cosigner ID.
func (m *TestMirror) ID() string {
	return m.cosignerID
}

// Cosign cosigns the checkpoint at Timestamp and returns the checkpoint
// cosignature line. It errors if the checkpoint is not of the cosigner's log.
func (m *TestMirror) Cosign(_ context.Context, cp *checkpoint.Checkpoint, _ []byte) ([]byte, error) {
	if cp.Origin != m.cosigner.Origin() {
		return nil, fmt.Errorf("checkpoint origin %q is not this mirror's log %q", cp.Origin, m.cosigner.Origin())
	}
	// A Cosigner signs with a zero timestamp only, so this is signed by hand.
	message, err := (&cosigned.Message{
		CosignerName: m.verifier.Name(),
		Timestamp:    Timestamp,
		LogOrigin:    cp.Origin,
		Start:        0,
		End:          uint64(cp.Tree.N), //nolint:gosec // G115: tree sizes are positive
		SubtreeHash:  cp.Tree.Hash,
	}).Marshal()
	if err != nil {
		return nil, err
	}
	signature, err := m.signer.Sign(nil, message, nil)
	if err != nil {
		return nil, err
	}
	return cosignature.SignatureLine(m.verifier.Name(), m.verifier.KeyHash(), Timestamp, signature)
}

// CosignSubtree returns the mirror's subtree signature over the whole tree of
// the checkpoint, as a mirror does once it has cosigned it. It errors if the
// checkpoint cosignature line is not this mirror's over cp.
func (m *TestMirror) CosignSubtree(_ context.Context, cp *checkpoint.Checkpoint, checkpointCosignatureLine []byte) ([]byte, error) {
	text, err := cp.Marshal()
	if err != nil {
		return nil, err
	}
	_, err = m.verifier.FilterByVerify(text, checkpointCosignatureLine)
	if err != nil {
		return nil, fmt.Errorf("checkpoint cosignature line is not this mirror's: %w", err)
	}
	zeroTimestampCosignature, err := m.cosigner.CosignCheckpoint(cp.Tree)
	if err != nil {
		return nil, err
	}
	return cosignature.RawSignature(zeroTimestampCosignature)
}
