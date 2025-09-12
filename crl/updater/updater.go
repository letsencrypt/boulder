package updater

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/protobuf/types/known/timestamppb"

	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/crl"
	cspb "github.com/letsencrypt/boulder/crl/storer/proto"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

type crlUpdater struct {
	issuers        map[issuance.NameID]*issuance.Certificate
	numShards      int
	shardWidth     time.Duration
	lookbackPeriod time.Duration
	updatePeriod   time.Duration
	updateTimeout  time.Duration
	maxParallelism int
	maxAttempts    int

	cacheControl  string
	expiresMargin time.Duration

	sa sapb.StorageAuthorityClient
	ca capb.CRLGeneratorClient
	cs cspb.CRLStorerClient

	tickHistogram  *prometheus.HistogramVec
	updatedCounter *prometheus.CounterVec

	log blog.Logger
	clk clock.Clock
}

func NewUpdater(
	issuers []*issuance.Certificate,
	numShards int,
	shardWidth time.Duration,
	lookbackPeriod time.Duration,
	updatePeriod time.Duration,
	updateTimeout time.Duration,
	maxParallelism int,
	maxAttempts int,
	cacheControl string,
	expiresMargin time.Duration,
	sa sapb.StorageAuthorityClient,
	ca capb.CRLGeneratorClient,
	cs cspb.CRLStorerClient,
	stats prometheus.Registerer,
	log blog.Logger,
	clk clock.Clock,
) (*crlUpdater, error) {
	issuersByNameID := make(map[issuance.NameID]*issuance.Certificate, len(issuers))
	for _, issuer := range issuers {
		issuersByNameID[issuer.NameID()] = issuer
	}

	if numShards < 1 {
		return nil, fmt.Errorf("must have positive number of shards, got: %d", numShards)
	}

	if updatePeriod >= 24*time.Hour {
		return nil, fmt.Errorf("must update CRLs at least every 24 hours, got: %s", updatePeriod)
	}

	if updateTimeout >= updatePeriod {
		return nil, fmt.Errorf("update timeout must be less than period: %s !< %s", updateTimeout, updatePeriod)
	}

	if lookbackPeriod < 2*updatePeriod {
		return nil, fmt.Errorf("lookbackPeriod must be at least 2x updatePeriod: %s !< 2 * %s", lookbackPeriod, updatePeriod)
	}

	if maxParallelism <= 0 {
		maxParallelism = 1
	}

	if maxAttempts <= 0 {
		maxAttempts = 1
	}

	tickHistogram := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "crl_updater_ticks",
		Help:    "A histogram of crl-updater tick latencies labeled by issuer and result",
		Buckets: []float64{0.01, 0.2, 0.5, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000},
	}, []string{"issuer", "result"})
	stats.MustRegister(tickHistogram)

	updatedCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "crl_updater_generated",
		Help: "A counter of CRL generation calls labeled by result",
	}, []string{"issuer", "result"})
	stats.MustRegister(updatedCounter)

	return &crlUpdater{
		issuersByNameID,
		numShards,
		shardWidth,
		lookbackPeriod,
		updatePeriod,
		updateTimeout,
		maxParallelism,
		maxAttempts,
		cacheControl,
		expiresMargin,
		sa,
		ca,
		cs,
		tickHistogram,
		updatedCounter,
		log,
		clk,
	}, nil
}

// updateShardWithRetry calls updateShard repeatedly (with exponential backoff
// between attempts) until it succeeds or the max number of attempts is reached.
func (cu *crlUpdater) updateShardWithRetry(ctx context.Context, atTime time.Time, issuerNameID issuance.NameID, shardIdx int) error {
	deadline := cu.clk.Now().Add(cu.updateTimeout)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	_, err := cu.sa.LeaseCRLShard(ctx, &sapb.LeaseCRLShardRequest{
		IssuerNameID: int64(issuerNameID),
		MinShardIdx:  int64(shardIdx),
		MaxShardIdx:  int64(shardIdx),
		Until:        timestamppb.New(deadline.Add(time.Minute)),
	})
	if err != nil {
		return fmt.Errorf("leasing shard: %w", err)
	}

	crlID := crl.Id(issuerNameID, shardIdx, crl.Number(atTime))

	for i := range cu.maxAttempts {
		// core.RetryBackoff always returns 0 when its first argument is zero.
		sleepTime := core.RetryBackoff(i, time.Second, time.Minute, 2)
		if i != 0 {
			cu.log.Errf(
				"Generating CRL failed, will retry in %vs: id=[%s] err=[%s]",
				sleepTime.Seconds(), crlID, err)
		}
		cu.clk.Sleep(sleepTime)

		err = cu.updateShard(ctx, atTime, issuerNameID, shardIdx)
		if err == nil {
			break
		}
	}
	if err != nil {
		return err
	}

	// Notify the database that that we're done.
	_, err = cu.sa.UpdateCRLShard(ctx, &sapb.UpdateCRLShardRequest{
		IssuerNameID: int64(issuerNameID),
		ShardIdx:     int64(shardIdx),
		ThisUpdate:   timestamppb.New(atTime),
	})
	if err != nil {
		return fmt.Errorf("updating db metadata: %w", err)
	}

	return nil
}

// updateShard processes a single shard. It computes the shard's boundaries, gets
// the list of revoked certs in that shard from the SA, gets the CA to sign the
// resulting CRL, and gets the crl-storer to upload it. It returns an error if
// any of these operations fail.
func (cu *crlUpdater) updateShard(ctx context.Context, atTime time.Time, issuerNameID issuance.NameID, shardIdx int) (err error) {
	if shardIdx <= 0 {
		return fmt.Errorf("invalid shard %d", shardIdx)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	crlID := crl.Id(issuerNameID, shardIdx, crl.Number(atTime))

	start := cu.clk.Now()
	defer func() {
		// This func closes over the named return value `err`, so can reference it.
		result := "success"
		if err != nil {
			result = "failed"
		}
		cu.tickHistogram.WithLabelValues(cu.issuers[issuerNameID].Subject.CommonName, result).Observe(cu.clk.Since(start).Seconds())
		cu.updatedCounter.WithLabelValues(cu.issuers[issuerNameID].Subject.CommonName, result).Inc()
	}()

	cu.log.Infof("Generating CRL shard: id=[%s]", crlID)

	// Query for unexpired certificates, with padding to ensure that revoked certificates show
	// up in at least one CRL, even if they expire between revocation and CRL generation.
	expiresAfter := cu.clk.Now().Add(-cu.lookbackPeriod)

	saStream, err := cu.sa.GetRevokedCertsByShard(ctx, &sapb.GetRevokedCertsByShardRequest{
		IssuerNameID:  int64(issuerNameID),
		ShardIdx:      int64(shardIdx),
		ExpiresAfter:  timestamppb.New(expiresAfter),
		RevokedBefore: timestamppb.New(atTime),
	})
	if err != nil {
		return fmt.Errorf("GetRevokedCertsByShard: %w", err)
	}

	var crlEntries []*proto.CRLEntry
	for {
		entry, err := saStream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("retrieving entry from SA: %w", err)
		}
		crlEntries = append(crlEntries, entry)
	}

	cu.log.Infof("Queried SA for CRL shard: id=[%s] shardIdx=[%d] numEntries=[%d]", crlID, shardIdx, len(crlEntries))

	// Send the full list of CRL Entries to the CA.
	caStream, err := cu.ca.GenerateCRL(ctx)
	if err != nil {
		return fmt.Errorf("connecting to CA: %w", err)
	}

	err = caStream.Send(&capb.GenerateCRLRequest{
		Payload: &capb.GenerateCRLRequest_Metadata{
			Metadata: &capb.CRLMetadata{
				IssuerNameID: int64(issuerNameID),
				ThisUpdate:   timestamppb.New(atTime),
				ShardIdx:     int64(shardIdx),
			},
		},
	})
	if err != nil {
		return fmt.Errorf("sending CA metadata: %w", err)
	}

	for _, entry := range crlEntries {
		err = caStream.Send(&capb.GenerateCRLRequest{
			Payload: &capb.GenerateCRLRequest_Entry{
				Entry: entry,
			},
		})
		if err != nil {
			return fmt.Errorf("sending entry to CA: %w", err)
		}
	}

	err = caStream.CloseSend()
	if err != nil {
		return fmt.Errorf("closing CA request stream: %w", err)
	}

	// Receive the full bytes of the signed CRL from the CA.
	crlLen := 0
	crlHash := sha256.New()
	var crlChunks [][]byte
	for {
		out, err := caStream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("receiving CRL bytes: %w", err)
		}

		crlLen += len(out.Chunk)
		crlHash.Write(out.Chunk)
		crlChunks = append(crlChunks, out.Chunk)
	}

	// Send the full bytes of the signed CRL to the Storer.
	csStream, err := cu.cs.UploadCRL(ctx)
	if err != nil {
		return fmt.Errorf("connecting to CRLStorer: %w", err)
	}

	err = csStream.Send(&cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_Metadata{
			Metadata: &cspb.CRLMetadata{
				IssuerNameID: int64(issuerNameID),
				Number:       atTime.UnixNano(),
				ShardIdx:     int64(shardIdx),
				CacheControl: cu.cacheControl,
				Expires:      timestamppb.New(atTime.Add(cu.updatePeriod).Add(cu.expiresMargin)),
			},
		},
	})
	if err != nil {
		return fmt.Errorf("sending CRLStorer metadata: %w", err)
	}

	for _, chunk := range crlChunks {
		err = csStream.Send(&cspb.UploadCRLRequest{
			Payload: &cspb.UploadCRLRequest_CrlChunk{
				CrlChunk: chunk,
			},
		})
		if err != nil {
			return fmt.Errorf("uploading CRL bytes: %w", err)
		}
	}

	_, err = csStream.CloseAndRecv()
	if err != nil {
		return fmt.Errorf("closing CRLStorer upload stream: %w", err)
	}

	cu.log.Infof(
		"Generated CRL shard: id=[%s] size=[%d] hash=[%x]",
		crlID, crlLen, crlHash.Sum(nil))

	return nil
}
