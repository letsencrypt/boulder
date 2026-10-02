package mtcb

import (
	"context"
	"crypto"
	"crypto/mldsa"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jmhodges/clock"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/mod/sumdb/tlog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	mtcbpb "github.com/letsencrypt/boulder/mtcb/proto"
	"github.com/letsencrypt/boulder/trees/checkpoint"
	"github.com/letsencrypt/boulder/trees/cosignature"
	"github.com/letsencrypt/boulder/trees/entry"
	"github.com/letsencrypt/boulder/trees/issuancelog"
	"github.com/letsencrypt/boulder/trees/proof"
	"github.com/letsencrypt/boulder/trees/pubkey"
	"github.com/letsencrypt/boulder/trees/tiles"
	"github.com/letsencrypt/boulder/trees/treedb"
)

// checkpointDB is the subset of treedb.Impl the mtcb uses, so tests can supply
// checkpoints without a database.
type checkpointDB interface {
	GetCheckpointSubtree(ctx context.Context, mtcLogID string, id int64) (*treedb.CheckpointSubtreeModel, error)
}

type mtcb struct {
	mtcbpb.UnimplementedMTCBServer

	issuers map[string]*issuance.Certificate

	checkpoints checkpointDB
	s3c         simpleS3

	log blog.Logger
	clk clock.Clock
}

var _ mtcbpb.MTCBServer = &mtcb{}

// New creates a new MTCB service.
func New(
	issuers []*issuance.Certificate,
	checkpoints checkpointDB,
	s3c simpleS3,
	logger blog.Logger,
	clk clock.Clock,
) (*mtcb, error) {
	// TODO: Make this a map of MTCA IDs to (certificate, checkpointDB), so that a single MTCB
	// can talk to multiple different databases to build certs for multiple
	// different CAs.
	issuersMap := make(map[string]*issuance.Certificate)
	for _, issuer := range issuers {
		caID, err := issuer.MTCAID()
		if err != nil {
			return nil, fmt.Errorf("computing MTCA ID: %w", err)
		}

		_, ok := issuer.PublicKey.(*mldsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("issuer %q not an ML-DSA pubkey (%T)", caID, issuer.PublicKey)
		}
		issuersMap[caID] = issuer
	}

	m := &mtcb{
		issuers:     issuersMap,
		checkpoints: checkpoints,
		s3c:         s3c,
		log:         logger,
		clk:         clk,
	}

	return m, nil
}

// simpleS3 matches the subset of the s3.Client interface which we use, to allow
// simpler mocking in tests.
type simpleS3 interface {
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	Bucket() string
}

// StandaloneReady checks if the requested TBSCertificateLogEntry is ready to be built into a standalone certificate.
//
// Note that this only checks the contents of the `checkpointSubtrees` table and not the latest checkpoint signed note
// from tile storage.
func (m *mtcb) StandaloneReady(ctx context.Context, req *mtcbpb.StandaloneReadyRequest) (*mtcbpb.StandaloneReadyResponse, error) {
	if core.IsAnyNilOrZero(req.MtcLogID, req.MtcSerialNumber, req.MtcSubtreeID) {
		return nil, errors.New("incomplete gRPC request")
	}

	requestedLogID, err := issuancelog.ParseID(req.MtcLogID)
	if err != nil {
		return nil, fmt.Errorf("parsing MTCLogID: %s", err)
	}

	_, ok := m.issuers[requestedLogID.CAID]
	if !ok {
		return nil, fmt.Errorf("no issuer configured for requested MTC log ID %q", requestedLogID.String())
	}

	requestedLogNumber, entryIndex, err := core.DecodeMTCSerial(req.MtcSerialNumber)
	if err != nil {
		return nil, err
	}

	if requestedLogNumber != requestedLogID.LogNumber {
		return nil, fmt.Errorf("serial %016x encodes log number %d, but requested MTC log ID is %q", req.MtcSerialNumber, requestedLogNumber, req.MtcLogID)
	}

	subtree, err := m.checkpoints.GetCheckpointSubtree(ctx, requestedLogID.String(), req.MtcSubtreeID)
	if err != nil {
		return nil, err
	}

	isReady, err := ready(subtree, uint64(entryIndex)) //nolint:gosec // G115: entryIndex is positive from DecodeMTCSerial
	if err != nil {
		return nil, err
	}

	return &mtcbpb.StandaloneReadyResponse{Ready: isReady}, nil
}

func (m *mtcb) GetStandalone(ctx context.Context, req *mtcbpb.StandaloneRequest) (*mtcbpb.StandaloneResponse, error) {
	if core.IsAnyNilOrZero(req.MtcLogID, req.MtcSerialNumber, req.MtcSubtreeID) {
		return nil, errors.New("incomplete gRPC request")
	}

	requestedLogID, err := issuancelog.ParseID(req.MtcLogID)
	if err != nil {
		return nil, err
	}

	_, ok := m.issuers[requestedLogID.CAID]
	if !ok {
		return nil, fmt.Errorf("no issuer configured for requested MTC log ID %q", requestedLogID.String())
	}

	requestedLogNumber, entryIndex, err := core.DecodeMTCSerial(req.MtcSerialNumber)
	if err != nil {
		return nil, err
	}
	if requestedLogNumber != requestedLogID.LogNumber {
		return nil, fmt.Errorf("serial %016x encodes log number %d, but requested MTC log ID is %q", req.MtcSerialNumber, requestedLogNumber, req.MtcLogID)
	}

	// Fetch the relevant subtree from the database.
	subtree, err := m.checkpoints.GetCheckpointSubtree(ctx, requestedLogID.String(), req.MtcSubtreeID)
	if err != nil {
		return nil, err
	}

	isReady, err := ready(subtree, uint64(entryIndex)) //nolint:gosec // G115: entryIndex is positive from DecodeMTCSerial
	if err != nil {
		return nil, err
	}
	if !isReady {
		return nil, fmt.Errorf("not ready to build standalone for %q %016x", requestedLogID, req.MtcSerialNumber)
	}

	// Fetch the latest checkpoint. We'll need the latest treesize to fetch tiles.
	latestCheckpoint, err := m.readCheckpoint(ctx, requestedLogID)
	if err != nil {
		return nil, fmt.Errorf("getting latest checkpoint: %s", err)
	}

	if subtree.SubtreeEnd > uint64(latestCheckpoint.Tree.N) { //nolint:gosec // G115: TreeSize is positive
		return nil, fmt.Errorf("subtreeEnd is greater than treeSize (%d > %d)",
			subtree.SubtreeEnd, latestCheckpoint.Tree.N)
	}

	// Fetch the tbsCertificateLogEntry and pubkey from the log.
	entryBundle, pubkeyBundle, err := tiles.ReadBundles(
		ctx,
		m.s3c,
		entryIndex,
		latestCheckpoint.Tree.N,
		requestedLogID.TilePrefix())
	if err != nil {
		return nil, fmt.Errorf("reading bundles: %w", err)
	}

	ebr := entry.NewBundleReader(entryBundle)
	pbr := pubkey.NewBundleReader(pubkeyBundle)

	for i := entryIndex - (entryIndex % 256); i < entryIndex; i++ {
		// TODO: using ReadEntry for these is very inefficient, because it parses
		// each entry instead of just skipping past the bytes.
		_, _, err := ebr.ReadEntry()
		if err != nil {
			return nil, fmt.Errorf("while scanning entry tile: %w", err)
		}

		_, _, err = pbr.ReadPubkey()
		if err != nil {
			return nil, fmt.Errorf("while scanning pubkey tile: %w", err)
		}
	}

	mtcle, _, err := ebr.ReadEntry()
	if err != nil {
		return nil, fmt.Errorf("while reading entry: %w", err)
	}

	pubkey, _, err := pbr.ReadPubkey()
	if err != nil {
		return nil, fmt.Errorf("while reading pubkey: %w", err)
	}

	// Build the inclusion proof from the log.
	tr := tiles.NewTileReader(ctx, m.s3c, requestedLogID.TilePrefix())
	// The tile reader has to know the latest tree size, while the proof
	// should go to the size of the subtree.
	hr := tlog.TileHashReader(latestCheckpoint.Tree, tr)

	inclusionProof, err := tlog.ProveRecord(
		int64(subtree.SubtreeEnd), //nolint:gosec // G115: SubtreeEnd is less than 1<<48.
		entryIndex,
		hr)
	if err != nil {
		return nil, fmt.Errorf("computing inclusion proof: %w", err)
	}

	// Build the cert from all of the above.
	tbs, err := mtcle.ToTBSCertificate(req.MtcSerialNumber, pubkey.Pubkey(), crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("building tbsCertificate: %w", err)
	}

	sig := proof.MTCProof{
		Start:          0,
		End:            subtree.SubtreeEnd,
		InclusionProof: inclusionProof,
		Signatures: []*proof.SubtreeSignature{
			{CosignerID: []byte(requestedLogID.CAID), Signature: subtree.MTCASignature},
			{CosignerID: []byte(*subtree.MirrorID), Signature: subtree.MirrorSignature},
		},
	}
	certBytes, err := buildCertificate(tbs, &sig)
	if err != nil {
		return nil, err
	}

	return &mtcbpb.StandaloneResponse{CertDER: certBytes}, nil
}

func ready(subtree *treedb.CheckpointSubtreeModel, entryIndex uint64) (bool, error) {
	err := subtree.Valid()
	if err != nil {
		return false, fmt.Errorf("validating checkpoint subtree %d: %w", subtree.ID, err)
	}

	if entryIndex < subtree.SubtreeStart || entryIndex >= subtree.SubtreeEnd {
		return false, fmt.Errorf("entryIndex is not in subtree ID %d [%d, %d)",
			subtree.ID, subtree.SubtreeStart, subtree.SubtreeEnd)
	}

	if subtree.SubtreeStart != 0 {
		return false, fmt.Errorf("inclusion proofs from start > 0 not yet supported")
	}

	return subtree.Mirrored(), nil
}

// buildCertificate wraps a DER-encoded tbsCertificate and an MTCProof into a
// DER-encoded RFC 5280 Certificate.
func buildCertificate(tbs []byte, sig *proof.MTCProof) ([]byte, error) {
	sigBytes, err := sig.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshaling MTCProof: %w", err)
	}

	b := cryptobyte.NewBuilder(nil)
	// The Certificate SEQUENCE
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		// The tbsCertificate SEQUENCE
		b.AddBytes(tbs)
		// The signatureAlgorithm SEQUENCE
		b.AddBytes(proof.SigAlgEncoded())
		// The signature BIT STRING
		b.AddASN1BitString(sigBytes)
	})

	certBytes, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("serializing certificate: %w", err)
	}

	return certBytes, nil
}

// readCheckpoint returns the current checkpoint for a given logID.
func (m *mtcb) readCheckpoint(ctx context.Context, logID issuancelog.ID) (*checkpoint.Checkpoint, error) {
	bucket := m.s3c.Bucket()
	path := logID.CheckpointPath()
	out, err := m.s3c.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &path})
	if err != nil {
		return nil, fmt.Errorf("reading s3://%s/%s: %w", bucket, path, err)
	}
	defer out.Body.Close()

	body, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("reading s3://%s/%s: %w", bucket, path, err)
	}

	issuer, ok := m.issuers[logID.CAID]
	if !ok {
		return nil, fmt.Errorf("no issuer configured for MTCAID %q", logID.CAID)
	}

	pubKey, ok := issuer.Certificate.PublicKey.(*mldsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("issuer public key is %T, must be ML-DSA-44", issuer.Certificate.PublicKey)
	}

	verifier, err := cosignature.NewVerifier(logID.CAID, pubKey)
	if err != nil {
		return nil, fmt.Errorf("creating CA verifier: %s", err)
	}

	cp, _, err := checkpoint.Open(body, verifier)
	if err != nil {
		return nil, err
	}

	if cp.Origin != logID.Origin() {
		return nil, fmt.Errorf("checkpoint at s3://%s/%s: origin %q doesn't match expected %q",
			bucket, path, cp.Origin, logID.Origin())
	}

	return cp, nil
}

func (m *mtcb) GetLandmarkRelative(ctx context.Context, req *mtcbpb.LandmarkRelativeRequest) (*mtcbpb.LandmarkRelativeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetLandmarkRelative not implemented")
}
