package notmain

import (
	"context"
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jmhodges/clock"
	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/rocsp"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test/ocsp/helper"
	"golang.org/x/crypto/ocsp"
)

type client struct {
	issuers       []shortIDIssuer
	redis         *rocsp.WritingClient
	db            *sql.DB // optional
	ocspGenerator capb.OCSPGeneratorClient
	clk           clock.Clock
}

// processResult represents the result of attempting to sign and store status
// for a single certificateStatus ID. If `err` is non-nil, it indicates the
// attempt failed.
type processResult struct {
	id  uint64
	err error
}

func (cl *client) loadFromDB(ctx context.Context, speed ProcessingSpeed) error {
	// To scan the DB efficiently, we want to select only currently-valid certificates. There's a
	// handy expires index, but for selecting a large set of rows, using the primary key will be
	// more efficient. So first we find a good id to start with, then scan from there. Note: since
	// AUTO_INCREMENT can skip around a bit, we add padding to ensure we get all currently-valid
	// certificates.
	// TODO(#5783): Allow starting from a specific ID.
	startTime := cl.clk.Now().Add(-24 * time.Hour)
	var minID *int64
	err := cl.db.QueryRowContext(
		ctx,
		"SELECT MIN(id) FROM certificateStatus WHERE notAfter >= ?",
		startTime,
	).Scan(&minID)
	if err != nil {
		return fmt.Errorf("selecting minID: %w", err)
	}
	if minID == nil {
		return fmt.Errorf("no entries in certificateStatus (where notAfter >= %s)", startTime)
	}

	// Limit the rate of reading rows.
	frequency := time.Duration(float64(time.Second) / float64(time.Duration(speed.RowsPerSecond)))
	// a set of all inflight certificate statuses, indexed by their `ID`.
	inflightIDs := newInflight()
	statusesToSign := cl.scanFromDB(ctx, *minID, frequency, inflightIDs)

	results := make(chan processResult, speed.ParallelSigns)
	var runningSigners int32
	for i := 0; i < speed.ParallelSigns; i++ {
		atomic.AddInt32(&runningSigners, 1)
		go cl.signAndStoreResponses(ctx, statusesToSign, results, &runningSigners)
	}

	var successCount, errorCount int64

	for result := range results {
		inflightIDs.remove(result.id)
		if result.err != nil {
			errorCount++
			if errorCount < 10 ||
				(errorCount < 1000 && rand.Intn(1000) < 100) ||
				(errorCount < 100000 && rand.Intn(1000) < 10) ||
				(rand.Intn(1000) < 1) {
				log.Printf("error: %s", result.err)
			}
		} else {
			successCount++
		}

		if (successCount+errorCount)%10 == 0 {
			log.Printf("stored %d responses, %d errors", successCount, errorCount)
		}
	}

	log.Printf("done. processed %d successes and %d errors\n", successCount, errorCount)
	if inflightIDs.len() != 0 {
		return fmt.Errorf("inflightIDs non-empty! has %d items, lowest %d", inflightIDs.len(), inflightIDs.min())
	}

	return nil
}

// scanFromDB scans certificateStatus rows from the DB, starting with `minID`, and writes them to
// its output channel at a maximum frequency of `frequency`. When it's read all available rows, it
// closes its output channel and exits.
// If there is an error, it logs the error, closes its output channel, and exits.
func (cl *client) scanFromDB(ctx context.Context, minID int64, frequency time.Duration, inflightIDs *inflight) <-chan *sa.CertStatusMetadata {
	statusesToSign := make(chan *sa.CertStatusMetadata)
	go func() {
		defer close(statusesToSign)
		err := cl.scanFromDBInner(ctx, minID, frequency, statusesToSign, inflightIDs)
		if err != nil {
			log.Printf("error scanning rows: %s", err)
		}
	}()
	return statusesToSign
}

func (cl *client) scanFromDBInner(ctx context.Context, minID int64, frequency time.Duration, output chan<- *sa.CertStatusMetadata, inflightIDs *inflight) error {
	rowTicker := time.NewTicker(frequency)

	query := fmt.Sprintf("SELECT %s FROM certificateStatus WHERE id >= ?",
		strings.Join(sa.CertStatusMetadataFields(), ", "))
	rows, err := cl.db.QueryContext(ctx, query, minID)
	if err != nil {
		return fmt.Errorf("scanning certificateStatus: %w", err)
	}
	defer func() {
		rerr := rows.Close()
		if rerr != nil {
			log.Printf("closing rows: %s", rerr)
		}
	}()

	var scanned int
	var previousID int64
	for rows.Next() {
		<-rowTicker.C

		status := new(sa.CertStatusMetadata)
		if err := sa.ScanCertStatusMetadataRow(rows, status); err != nil {
			return fmt.Errorf("scanning row %d (previous ID %d): %w", scanned, previousID, err)
		}
		scanned++
		inflightIDs.add(uint64(status.ID))
		// Emit a log line every 100000 rows. For our current ~215M rows, that
		// will emit about 2150 log lines. This probably strikes a good balance
		// between too spammy and having a reasonably frequent checkpoint.
		if scanned%100000 == 0 {
			log.Printf("scanned %d certificateStatus rows. minimum inflight ID %d", scanned, inflightIDs.min())
		}
		output <- status
		previousID = status.ID
	}
	return nil
}

type signedResponse struct {
	der []byte
	ttl time.Duration
}

// signAndStoreResponses consumes cert statuses on its input channel and writes them to its output
// channel. Before returning, it atomically decrements the provided runningSigners int. If the
// result is 0, indicating this was the last running signer, it closes its output channel.
func (cl *client) signAndStoreResponses(ctx context.Context, input <-chan *sa.CertStatusMetadata, output chan processResult, runningSigners *int32) {
	defer func() {
		if atomic.AddInt32(runningSigners, -1) <= 0 {
			close(output)
		}
	}()
	for status := range input {
		ocspReq := &capb.GenerateOCSPRequest{
			Serial:    status.Serial,
			IssuerID:  status.IssuerID,
			Status:    string(status.Status),
			Reason:    int32(status.RevokedReason),
			RevokedAt: status.RevokedDate.UnixNano(),
		}
		result, err := cl.ocspGenerator.GenerateOCSP(ctx, ocspReq)
		if err != nil {
			output <- processResult{id: uint64(status.ID), err: err}
			continue
		}
		// ttl is the lifetime of the certificate
		ttl := cl.clk.Now().Sub(status.NotAfter)
		issuer, err := findIssuerByID(status.IssuerID, cl.issuers)
		if err != nil {
			output <- processResult{id: uint64(status.ID), err: err}
			continue
		}

		err = cl.redis.StoreResponse(ctx, result.Response, issuer.shortID, ttl)
		if err != nil {
			output <- processResult{id: uint64(status.ID), err: err}
		} else {
			output <- processResult{id: uint64(status.ID), err: nil}
		}
	}
}

type expiredError struct {
	serial string
	ago    time.Duration
}

func (e expiredError) Error() string {
	return fmt.Sprintf("response for %s expired %s ago", e.serial, e.ago)
}

func (cl *client) storeResponsesFromFiles(ctx context.Context, files []string) error {
	for _, respFile := range files {
		respBytes, err := ioutil.ReadFile(respFile)
		if err != nil {
			return fmt.Errorf("reading response file %q: %w", respFile, err)
		}
		err = cl.storeResponse(ctx, respBytes, nil)
		if err != nil {
			return err
		}
	}
	return nil
}

func (cl *client) storeResponse(ctx context.Context, respBytes []byte, ttl *time.Duration) error {
	resp, err := ocsp.ParseResponse(respBytes, nil)
	if err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}
	issuer, err := findIssuerByName(resp, cl.issuers)
	if err != nil {
		return fmt.Errorf("finding issuer for response: %w", err)
	}

	// Re-parse the response, this time verifying with the appropriate issuer
	resp, err = ocsp.ParseResponse(respBytes, issuer.Certificate.Certificate)
	if err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	serial := core.SerialToString(resp.SerialNumber)

	if resp.NextUpdate.Before(cl.clk.Now()) {
		return expiredError{
			serial: serial,
			ago:    cl.clk.Now().Sub(resp.NextUpdate),
		}
	}

	// Note: Here we set the TTL to slightly more than the lifetime of the
	// OCSP response. In ocsp-updater we'll want to set it to the lifetime
	// of the certificate, so that the metadata field doesn't fall out of
	// storage even if we are down for days. However, in this tool we don't
	// have the full certificate, so this will do.
	if ttl == nil {
		ttl_temp := resp.NextUpdate.Sub(cl.clk.Now()) + time.Hour
		ttl = &ttl_temp
	}

	log.Printf("storing response for %s, generated %s, ttl %g hours",
		serial,
		resp.ThisUpdate,
		ttl.Hours(),
	)

	err = cl.redis.StoreResponse(ctx, respBytes, issuer.shortID, *ttl)
	if err != nil {
		return fmt.Errorf("storing response: %w", err)
	}

	retrievedResponse, err := cl.redis.GetResponse(ctx, serial)
	if err != nil {
		return fmt.Errorf("getting response: %w", err)
	}

	parsedRetrievedResponse, err := ocsp.ParseResponse(retrievedResponse, issuer.Certificate.Certificate)
	if err != nil {
		return fmt.Errorf("parsing retrieved response: %w", err)
	}
	log.Printf("retrieved %s", helper.PrettyResponse(parsedRetrievedResponse))
	return nil
}
