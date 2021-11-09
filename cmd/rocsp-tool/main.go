package notmain

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jmhodges/clock"
	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/issuance"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/rocsp"
	rocsp_config "github.com/letsencrypt/boulder/rocsp/config"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test/ocsp/helper"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"
)

type config struct {
	ROCSPTool struct {
		Redis rocsp_config.RedisConfig
		// Issuers is a map from filenames to short issuer IDs.
		// Each filename must contain an issuer certificate. The short issuer
		// IDs are arbitrarily assigned and must be consistent across OCSP
		// components. For production we'll use the number part of the CN, i.e.
		// E1 -> 1, R3 -> 3, etc.
		Issuers map[string]int

		// If using load-from-db, this provides credentials to connect to the DB
		// and the CA. Otherwise, it's optional.
		LoadFromDB *LoadFromDBConfig
	}
}

// LoadFromDBConfig provides the credentials and configuration needed to load
// data from the certificateStatuses table in the DB and get it signed.
type LoadFromDBConfig struct {
	// Credentials to connect to the DB.
	DB cmd.DBConfig
	// Credentials to request OCSP signatures from the CA.
	GRPCTLS cmd.TLSConfig
	// Timeouts and hostnames for the CA.
	OCSPGeneratorService cmd.GRPCClientConfig
	// How fast to process rows.
	Speed ProcessingSpeed
}

type ProcessingSpeed struct {
	// If using load-from-db, this limits how many items per second we
	// scan from the DB. We might go slower than this depending on how fast
	// we read rows from the DB, but we won't go faster. Defaults to 2000.
	RowsPerSecond int
	// If using load-from-db, this controls how many parallel requests to
	// boulder-ca for OCSP signing we can make. Defaults to 100.
	ParallelSigns int
}

func init() {
	cmd.RegisterCommand("rocsp-tool", main)
}

func main() {
	if err := main2(); err != nil {
		log.Fatal(err)
	}
}

type ShortIDIssuer struct {
	*issuance.Certificate
	subject pkix.RDNSequence
	shortID byte
}

func loadIssuers(input map[string]int) ([]ShortIDIssuer, error) {
	var issuers []ShortIDIssuer
	for issuerFile, shortID := range input {
		if shortID > 255 || shortID < 0 {
			return nil, fmt.Errorf("invalid shortID %d (must be byte)", shortID)
		}
		cert, err := issuance.LoadCertificate(issuerFile)
		if err != nil {
			return nil, fmt.Errorf("reading issuer: %w", err)
		}
		var subject pkix.RDNSequence
		_, err = asn1.Unmarshal(cert.Certificate.RawSubject, &subject)
		if err != nil {
			return nil, fmt.Errorf("parsing issuer.RawSubject: %w", err)
		}
		var shortID byte = byte(shortID)
		for _, issuer := range issuers {
			if issuer.shortID == shortID {
				return nil, fmt.Errorf("duplicate shortID in config file: %d (for %q and %q)", shortID, issuer.subject, subject)
			}
			if !issuer.IsCA {
				return nil, fmt.Errorf("certificate for %q is not a CA certificate", subject)
			}
		}
		issuers = append(issuers, ShortIDIssuer{cert, subject, shortID})
	}
	return issuers, nil
}

func findIssuer(resp *ocsp.Response, issuers []ShortIDIssuer) (*ShortIDIssuer, error) {
	var responder pkix.RDNSequence
	_, err := asn1.Unmarshal(resp.RawResponderName, &responder)
	if err != nil {
		return nil, fmt.Errorf("parsing resp.RawResponderName: %w", err)
	}
	var responders strings.Builder
	for _, issuer := range issuers {
		fmt.Fprintf(&responders, "%s\n", issuer.subject)
		if bytes.Equal(issuer.RawSubject, resp.RawResponderName) {
			return &issuer, nil
		}
	}
	return nil, fmt.Errorf("no issuer found matching OCSP response for %s. Available issuers:\n%s\n", responder, responders.String())
}

func main2() error {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	rand.Seed(time.Now().UnixNano())

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	if err != nil {
		return fmt.Errorf("reading JSON config file: %w", err)
	}

	issuers, err := loadIssuers(c.ROCSPTool.Issuers)
	if err != nil {
		return fmt.Errorf("loading issuers: %w", err)
	}
	if len(issuers) == 0 {
		return fmt.Errorf("'issuers' section of config JSON is required.")
	}
	clk := cmd.Clock()
	redisClient, err := rocsp_config.MakeClient(&c.ROCSPTool.Redis, clk)
	if err != nil {
		return fmt.Errorf("making client: %w", err)
	}

	var db *sql.DB
	var ocspGenerator capb.OCSPGeneratorClient
	if c.ROCSPTool.LoadFromDB != nil {
		lfd := c.ROCSPTool.LoadFromDB
		db, err = configureDb(&lfd.DB)
		if err != nil {
			return fmt.Errorf("connecting to DB: %w", err)
		}

		ocspGenerator, err = configureOCSPGenerator(lfd.GRPCTLS,
			lfd.OCSPGeneratorService, clk, metrics.NoopRegisterer)
		if err != nil {
			return fmt.Errorf("configuring gRPC to CA: %w", err)
		}
		setDefault(&lfd.Speed.RowsPerSecond, 2000)
		setDefault(&lfd.Speed.ParallelSigns, 100)
	}

	if len(flag.Args()) < 1 {
		helpExit()
	}

	ctx := context.Background()
	cl := client{
		issuers:       issuers,
		redis:         redisClient,
		db:            db,
		ocspGenerator: ocspGenerator,
		clk:           clk,
	}
	switch flag.Arg(0) {
	case "store":
		err := cl.storeResponsesFromFiles(ctx, flag.Args()[1:])
		if err != nil {
			return err
		}
	case "load-from-db":
		if c.ROCSPTool.LoadFromDB == nil {
			return fmt.Errorf("config field LoadFromDB was missing")
		}
		err = cl.loadFromDB(ctx, c.ROCSPTool.LoadFromDB.Speed)
		if err != nil {
			return fmt.Errorf("loading OCSP responses from DB: %w", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unrecognized subcommand %q\n", flag.Arg(0))
		helpExit()
	}
	return nil
}

func helpExit() {
	fmt.Fprintf(os.Stderr, "Usage: %s [store|copy-from-db] --config path/to/config.json\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "  store -- for each command line arg, read that filename as an OCSP response and store it in Redis")
	fmt.Fprintln(os.Stderr, "  load-from-db -- scan the database for all OCSP entries for unexpired certificates, and store in Redis")
	fmt.Fprintln(os.Stderr)
	flag.PrintDefaults()
	os.Exit(1)
}

func configureOCSPGenerator(tlsConf cmd.TLSConfig, grpcConf cmd.GRPCClientConfig, clk clock.Clock, stats prometheus.Registerer) (capb.OCSPGeneratorClient, error) {
	tlsConfig, err := tlsConf.Load()
	if err != nil {
		return nil, fmt.Errorf("loading TLS config: %w", err)
	}
	clientMetrics := bgrpc.NewClientMetrics(stats)
	caConn, err := bgrpc.ClientSetup(&grpcConf, tlsConfig, clientMetrics, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to CA")
	return capb.NewOCSPGeneratorClient(caConn), nil
}

func configureDb(dbConfig *cmd.DBConfig) (*sql.DB, error) {
	if dbConfig == nil {
		return nil, nil
	}
	dsn, err := dbConfig.URL()
	if err != nil {
		return nil, fmt.Errorf("loading DB URL: %w", err)
	}

	conf, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("while parsing DSN from 'DBConnectFile': %s", err)
	}

	if len(conf.Params) == 0 {
		conf.Params = make(map[string]string)
	}
	conf.Params["tx_isolation"] = "'READ-UNCOMMITTED'"
	conf.Params["interpolateParams"] = "true"
	conf.Params["parseTime"] = "true"

	db, err := sql.Open("mysql", conf.FormatDSN())
	if err != nil {
		return nil, fmt.Errorf("couldn't setup database client: %s", err)
	}

	db.SetMaxOpenConns(dbConfig.MaxOpenConns)
	db.SetMaxIdleConns(dbConfig.MaxIdleConns)
	db.SetConnMaxLifetime(dbConfig.ConnMaxLifetime.Duration)
	db.SetConnMaxIdleTime(dbConfig.ConnMaxIdleTime.Duration)
	return db, nil
}

// setDefault sets the target to a default value, if it is zero.
func setDefault(target *int, def int) {
	if *target == 0 {
		*target = def
	}
}

type client struct {
	issuers       []ShortIDIssuer
	redis         *rocsp.WritingClient
	db            *sql.DB // optional
	ocspGenerator capb.OCSPGeneratorClient
	clk           clock.Clock
}

type inflight struct {
	sync.RWMutex
	items map[uint64]struct{}
}

func newInflight() *inflight {
	return &inflight{
		items: make(map[uint64]struct{}),
	}
}

func (i *inflight) add(n uint64) {
	i.Lock()
	defer i.Unlock()
	i.items[n] = struct{}{}
}

func (i *inflight) remove(n uint64) {
	i.Lock()
	defer i.Unlock()
	delete(i.items, n)
}

func (i *inflight) len() int {
	i.RLock()
	defer i.RUnlock()
	return len(i.items)
}

// min returns the numerically smallest key inflight. If nothing is inflight,
// it returns 0. Note: this takes O(n) time in the number of keys and should
// be called rarely.
func (i *inflight) min() uint64 {
	i.RLock()
	defer i.RUnlock()
	if len(i.items) == 0 {
		return 0
	}
	var min uint64
	for k := range i.items {
		if min == 0 {
			min = k
		}
		if k < min {
			min = k
		}
	}
	return min
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
		err = cl.storeResponse(ctx, result.Response, &ttl)
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
	issuer, err := findIssuer(resp, cl.issuers)
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
