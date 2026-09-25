package mtcb

import (
	"context"
	"crypto"
	"errors"
	"fmt"

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
	LatestCheckpoint(ctx context.Context, mtcLogID string) (*treedb.CheckpointModel, error)
}

type mtcb struct {
	mtcbpb.UnimplementedMTCBServer

	issuers map[string]struct{}

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
	// TODO: Make this a map of MTCA IDs to checkpointDBs, so that a single MTCB
	// can talk to multiple different databases to build certs for multiple
	// different CAs.
	issuersMap := make(map[string]struct{})
	for _, issuer := range issuers {
		caID, err := issuer.MTCAID()
		if err != nil {
			return nil, fmt.Errorf("computing MTCA ID: %w", err)
		}

		issuersMap[caID] = struct{}{}
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

// entryIndexBits is the width of the entry index in the low bits of a 64-bit
// MTC serial.
//
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-certificate-format
const entryIndexBits = 48

// splitMTCSerial takes a serial number and returns the log number and entry
// index encoded inside it.
func splitMTCSerial(serial uint64) (uint16, uint64) {
	// The log number is the top 16 bits of the 64-bit serial.
	logNum := uint16(serial >> entryIndexBits)

	// The entry index is the bottom 48 bits of the 64-bit serial.
	entryIndex := serial & (1<<entryIndexBits - 1)

	return logNum, entryIndex
}

// StandaloneReady checks if the requested TBSCertificateLogEntry is ready to be built into a stanadlone certificate.
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
		return nil, fmt.Errorf("misdirected request for MTC log ID %q", req.MtcLogID)
	}

	requestedLogNumber, entryIndex := splitMTCSerial(req.MtcSerialNumber)

	if requestedLogNumber != requestedLogID.LogNumber {
		return nil, fmt.Errorf("misdirected request for MTC ID %s and serial %016x",
			requestedLogID.String(), req.MtcSerialNumber)
	}

	subtree, err := m.checkpoints.GetCheckpointSubtree(ctx, requestedLogID.String(), req.MtcSubtreeID)
	if err != nil {
		return nil, err
	}

	ready, err := ready(subtree, entryIndex)
	if err != nil {
		return nil, err
	}

	return &mtcbpb.StandaloneReadyResponse{Ready: ready}, nil
}

func (m *mtcb) GetStandalone(ctx context.Context, req *mtcbpb.StandaloneRequest) (*mtcbpb.StandaloneResponse, error) {
	if core.IsAnyNilOrZero(req.MtcLogID, req.MtcSerialNumber, req.MtcSubtreeID) {
		return nil, errors.New("incomplete gRPC request")
	}

	logID, err := issuancelog.ParseID(req.MtcLogID)
	if err != nil {
		return nil, err
	}

	_, ok := m.issuers[logID.CAID]
	if !ok {
		return nil, fmt.Errorf("unrecognized MTCA ID %q", logID.CAID)
	}

	logNum, entryIndex := splitMTCSerial(req.MtcSerialNumber)
	if logNum != logID.LogNumber {
		return nil, fmt.Errorf("serial %d encodes log number %d, which is not log %q", req.MtcSerialNumber, logNum, req.MtcLogID)
	}
	entryIndexInt64 := int64(entryIndex) //nolint:gosec // G115: splitMTCSerial zeroes the top 16 bits of entryIndex, so it fits in an int64.

	// Fetch the latest checkpoint. We'll need the latest treesize to fetch tiles.
	// TODO: The latestCheckpoint table gets updated upon signing, and tile publication hasn't happened yet.
	// So we can wind up trying to read tiles that don't exist yet.  Read the checkpoint file from tile storage
	// instead of the latest checkpoint row from the DB.
	latestCheckpoint, err := m.checkpoints.LatestCheckpoint(ctx, logID.String())
	if err != nil {
		return nil, fmt.Errorf("getting latest checkpoint: %s", err)
	}
	err = latestCheckpoint.Valid()
	if err != nil {
		return nil, fmt.Errorf("validating checkpoint %d: %w", latestCheckpoint.ID, err)
	}

	// Fetch the relevant subtree from the database.
	subtree, err := m.checkpoints.GetCheckpointSubtree(ctx, logID.String(), req.MtcSubtreeID)
	if err != nil {
		return nil, err
	}

	isReady, err := ready(subtree, entryIndex)
	if err != nil {
		return nil, err
	}
	if !isReady {
		return nil, fmt.Errorf("not ready to build standalone for %q %016x", logID, req.MtcSerialNumber)
	}

	if subtree.SubtreeEnd > uint64(latestCheckpoint.TreeSize) { //nolint:gosec // G115: TreeSize is positive
		return nil, fmt.Errorf("subtreeEnd is greater than treeSize (%d > %d)",
			subtree.SubtreeEnd, latestCheckpoint.TreeSize)
	}

	// Fetch the tbsCertificateLogEntry and pubkey from the log.
	entryBundle, pubkeyBundle, err := tiles.ReadBundles(
		ctx,
		m.s3c,
		entryIndexInt64,
		latestCheckpoint.TreeSize,
		logID.TilePrefix())
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
	tr := tiles.NewTileReader(ctx, m.s3c, logID.TilePrefix())
	// The tile reader has to know the latest tree size, while the proof
	// should go to the size of the subtree.
	hr := tlog.TileHashReader(tlog.Tree{
		N:    latestCheckpoint.TreeSize,
		Hash: tlog.Hash(latestCheckpoint.RootHash),
	}, tr)

	if subtree.SubtreeStart != 0 {
		return nil, fmt.Errorf("inclusion proofs from start > 0 not yet supported")
	}

	inclusionProof, err := tlog.ProveRecord(
		int64(subtree.SubtreeEnd), //nolint:gosec // G115: SubtreeEnd is less than 1<<48.
		entryIndexInt64,
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
			{CosignerID: []byte(logID.CAID), Signature: subtree.MTCASignature},
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

func (m *mtcb) GetLandmarkRelative(ctx context.Context, req *mtcbpb.LandmarkRelativeRequest) (*mtcbpb.LandmarkRelativeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetLandmarkRelative not implemented")
}
