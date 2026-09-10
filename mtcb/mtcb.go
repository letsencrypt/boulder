//go:build go1.27

package mtcb

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jmhodges/clock"
	"github.com/zmap/zcrypto/cryptobyte"
	"golang.org/x/mod/sumdb/tlog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/letsencrypt/borp"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/db"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	mtcbpb "github.com/letsencrypt/boulder/mtcb/proto"
	"github.com/letsencrypt/boulder/trees/entry"
	"github.com/letsencrypt/boulder/trees/issuancelog"
	"github.com/letsencrypt/boulder/trees/proof"
	"github.com/letsencrypt/boulder/trees/pubkey"
	"github.com/letsencrypt/boulder/trees/tiles"
)

type mtcb struct {
	mtcbpb.UnimplementedMTCBServer

	issuers map[string]struct{}

	db  *db.WrappedMap
	s3c simpleS3

	log blog.Logger
	clk clock.Clock
}

var _ mtcbpb.MTCBServer = &mtcb{}

// New creates a new MTCB service.
func New(
	issuers []*issuance.Certificate,
	dbMap *borp.DbMap,
	s3c simpleS3,
	logger blog.Logger,
	clk clock.Clock,
) (*mtcb, error) {
	issuersMap := make(map[string]struct{})
	for _, issuer := range issuers {
		caID, err := getCAID(issuer.Certificate)
		if err != nil {
			return nil, fmt.Errorf("computing MTCA ID: %w", err)
		}

		issuersMap[caID] = struct{}{}
	}

	m := &mtcb{
		issuers: issuersMap,
		db:      initDB(dbMap),
		s3c:     s3c,
		log:     logger,
		clk:     clk,
	}

	return m, nil
}

// simpleS3 matches the subset of the s3.Client interface which we use, to allow
// simpler mocking in tests.
type simpleS3 interface {
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	Bucket() string
}

func getCAID(issuerCert *x509.Certificate) (string, error) {
	testingTrustAnchorIDOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 1}
	for _, attribute := range issuerCert.Subject.Names {
		if attribute.Type.Equal(testingTrustAnchorIDOID) {
			caID, ok := attribute.Value.(string)
			if !ok {
				return "", fmt.Errorf("invalid trust anchor attribute type %T", attribute.Value)
			}
			return caID, nil
		}
	}

	return "", fmt.Errorf("issuer subject %q did not contain trust anchor ID OID %q",
		issuerCert.Subject, testingTrustAnchorIDOID)
}

func initDB(dbMap *borp.DbMap) *db.WrappedMap {
	dbMap.AddTableWithName(checkpointRow{}, "checkpoints").SetKeys(true, "ID")
	return db.NewWrappedMap(dbMap)
}

// splitMTCSerial takes a hex-encoded serial number and returns the log number
// and entry index encoded inside it.
func splitMTCSerial(serial string) (uint16, uint64, error) {
	serialBytes, err := hex.DecodeString(serial)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to decode hex serial %q: %w", serial, err)
	}

	if len(serialBytes) < 1 || len(serialBytes) > 8 {
		return 0, 0, fmt.Errorf("serial must be a uint64, got %d bytes", len(serialBytes))
	}

	// The serial is always a 64-bit int. However, there might be many leading
	// zeroes which aren't represented in the hex string, so it needs to be
	// left-padded with zeroes out to 64 bits.
	var paddedSerialBytes [8]byte
	copy(paddedSerialBytes[8-len(serialBytes):8], serialBytes)

	// The log number is the top two bytes of the 64-bit serial.
	logNum := binary.BigEndian.Uint16(serialBytes[0:2])

	// The entry index is the bottom six bytes of the 64-bit serial. We use an
	// 8-byte array to hold it because Go doesn't have native 48-bit ints, and
	// zero the top bytes to clear out the log number.
	serialBytes[0] = 0
	serialBytes[1] = 0
	entryIndex := binary.BigEndian.Uint64(serialBytes[0:8])

	return logNum, entryIndex, nil
}

func (m *mtcb) GetStandalone(ctx context.Context, req *mtcbpb.StandaloneRequest) (*mtcbpb.StandaloneResponse, error) {
	// Step 0: Validate the request.
	if core.IsAnyNilOrZero(req.MtcaID, req.Serial) {
		return nil, errors.New("incomplete gRPC request")
	}

	_, ok := m.issuers[req.MtcaID]
	if !ok {
		return nil, fmt.Errorf("unrecognized MTCA ID %q", req.MtcaID)
	}

	logNum, entryIndex, err := splitMTCSerial(req.Serial)
	if err != nil {
		return nil, err
	}

	logID := issuancelog.ID{CAID: req.MtcaID, LogNumber: logNum}

	// Step 1: Fetch the relevant checkpoint from the database.
	// TODO: Eventually, fetch the relevant subtree instead.
	cp, err := m.containingCheckpoint(ctx, logID, entryIndex)
	if err != nil {
		return nil, err
	}

	// Step 2: Fetch the tbsCertificateLogEntry and pubkey from the log.
	tr := tiles.NewTileReader(ctx, m.s3c, logID.TilePrefix())

	entryTiles, err := tr.ReadTiles([]tlog.Tile{{
		L: -1, // TODO: use const for level
		N: int64(entryIndex) / 256,
		W: 256, // TODO: support non-full tiles
	}})
	if err != nil {
		return nil, fmt.Errorf("failed to read entry tile: %w", err)
	}

	pubkeyTiles, err := tr.ReadTiles([]tlog.Tile{{
		L: -2, // TODO: use const for level
		N: int64(entryIndex) / 256,
		W: 256, // TODO: support non-full tiles
	}})
	if err != nil {
		return nil, fmt.Errorf("failed to read pubkey tile: %w", err)
	}

	ebr := entry.NewBundleReader(entryTiles[0])
	pbr := pubkey.NewBundleReader(pubkeyTiles[0])

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

	// Step 3: Build the inclusion proof from the log.
	var rootHash tlog.Hash
	copy(rootHash[:], cp.RootHash)
	hr := tlog.TileHashReader(tlog.Tree{N: cp.TreeSize, Hash: rootHash}, tr)
	inclusionProof, err := tlog.ProveRecord(cp.TreeSize, int64(entryIndex), hr)
	if err != nil {
		return nil, fmt.Errorf("computing inclusion proof: %w", err)
	}

	// Step 4: Synthesize the cert from all of the above.
	tbs, err := mtcle.ToTBSCertificate(uint64(logNum)<<48|entryIndex, pubkey.Pubkey(), crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("synthesizing tbsCertificate: %w", err)
	}

	sig := proof.MTCProof{
		Start:          0,
		End:            uint64(cp.TreeSize),
		InclusionProof: inclusionProof,
		Signatures: []*proof.SubtreeSignature{
			{CosignerID: []byte(logID.CAID), Signature: cp.MTCASignature},
			{CosignerID: []byte(*cp.MirrorID), Signature: cp.MirrorSignature},
		},
	}
	sigBytes, err := sig.Marshal()
	if err != nil {
		return nil, fmt.Errorf("synthesizing mtcProof signature: %w", err)
	}

	b := cryptobyte.NewBuilder(nil)
	// The Certificate SEQUENCE
	b.AddASN1(asn1.TagSequence, func(b *cryptobyte.Builder) {
		// The tbsCertificate SEQUENCE
		b.AddASN1(asn1.TagSequence, func(b *cryptobyte.Builder) {
			b.AddBytes(tbs)
		})
		// The signatureAlgorithm SEQUENCE
		b.AddASN1(asn1.TagSequence, func(b *cryptobyte.Builder) {
			b.AddBytes(proof.SigAlgEncoded())
		})
		// The signature BIT STRING
		b.AddASN1BitString(sigBytes)
	})

	certBytes, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("synthesizing certificate: %w", err)
	}

	return &mtcbpb.StandaloneResponse{CertDER: certBytes}, nil
}

func (m *mtcb) GetLandmarkRelative(ctx context.Context, req *mtcbpb.LandmarkRelativeRequest) (*mtcbpb.LandmarkRelativeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetLandmarkRelative not implemented")
}

// checkpointRow is the database model of a signed and mirrored checkpoint.
type checkpointRow struct {
	ID              int64   `db:"id"`
	MTCLogID        string  `db:"mtcLogID"`
	MTCASignature   []byte  `db:"mtcaSignature"`
	MirrorID        *string `db:"mirrorID"` // nullable if not yet mirrored
	MirrorSignature []byte  `db:"mirrorSignature"`
	TreeSize        int64   `db:"treeSize"`
	RootHash        []byte  `db:"rootHash"`
}

func (m *mtcb) containingCheckpoint(ctx context.Context, logID issuancelog.ID, entryIndex uint64) (*checkpointRow, error) {
	var cp checkpointRow
	err := m.db.SelectOne(ctx, &cp,
		`SELECT id, mtcLogID, mtcaSignature, mirrorID, mirrorSignature, treeSize, rootHash
		 FROM checkpoints
		 WHERE mtcLogID = ? AND
		 			 treeSize > ?
		 ORDER BY treeSize
		 LIMIT 1`,
		logID.String(),
		entryIndex)
	if err != nil {
		return nil, fmt.Errorf("getting checkpoint for log %q index %d: %w", logID.String(), entryIndex, err)
	}

	return &cp, nil
}
