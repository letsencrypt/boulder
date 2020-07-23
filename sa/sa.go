package sa

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	jose "gopkg.in/square/go-jose.v2"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/db"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/identifier"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/revocation"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

type certCountFunc func(db db.Selector, domain string, earliest, latest time.Time) (int, error)

// SQLStorageAuthority defines a Storage Authority
type SQLStorageAuthority struct {
	dbMap *db.WrappedMap
	clk   clock.Clock
	log   blog.Logger

	// For RPCs that generate multiple, parallelizable SQL queries, this is the
	// max parallelism they will use (to avoid consuming too many MariaDB
	// threads).
	parallelismPerRPC int

	// We use function types here so we can mock out this internal function in
	// unittests.
	countCertificatesByName certCountFunc

	// rateLimitWriteErrors is a Counter for the number of times
	// a ratelimit update transaction failed during AddCertificate request
	// processing. We do not fail the overall AddCertificate call when ratelimit
	// transactions fail and so use this stat to maintain visibility into the rate
	// this occurs.
	rateLimitWriteErrors prometheus.Counter
}

// orderFQDNSet contains the SHA256 hash of the lowercased, comma joined names
// from a new-order request, along with the corresponding orderID, the
// registration ID, and the order expiry. This is used to find
// existing orders for reuse.
type orderFQDNSet struct {
	ID             int64
	SetHash        []byte
	OrderID        int64
	RegistrationID int64
	Expires        time.Time
}

// NewSQLStorageAuthority provides persistence using a SQL backend for
// Boulder. It will modify the given gorp.DbMap by adding relevant tables.
func NewSQLStorageAuthority(
	dbMap *db.WrappedMap,
	clk clock.Clock,
	logger blog.Logger,
	stats prometheus.Registerer,
	parallelismPerRPC int,
) (*SQLStorageAuthority, error) {
	SetSQLDebug(dbMap, logger)

	rateLimitWriteErrors := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "rate_limit_write_errors",
		Help: "number of failed ratelimit update transactions during AddCertificate",
	})
	stats.MustRegister(rateLimitWriteErrors)

	ssa := &SQLStorageAuthority{
		dbMap:                dbMap,
		clk:                  clk,
		log:                  logger,
		parallelismPerRPC:    parallelismPerRPC,
		rateLimitWriteErrors: rateLimitWriteErrors,
	}

	ssa.countCertificatesByName = ssa.countCertificates

	return ssa, nil
}

// GetRegistration obtains a Registration by ID
func (ssa *SQLStorageAuthority) GetRegistration(ctx context.Context, id int64) (core.Registration, error) {
	const query = "WHERE id = ?"
	model, err := selectRegistration(ssa.dbMap.WithContext(ctx), query, id)
	if err != nil {
		if db.IsNoRows(err) {
			return core.Registration{}, berrors.NotFoundError("registration with ID '%d' not found", id)
		}
		return core.Registration{}, err
	}

	return modelToRegistration(model)
}

// GetRegistrationByKey obtains a Registration by JWK
func (ssa *SQLStorageAuthority) GetRegistrationByKey(ctx context.Context, key *jose.JSONWebKey) (core.Registration, error) {
	const query = "WHERE jwk_sha256 = ?"
	if key == nil {
		return core.Registration{}, fmt.Errorf("key argument to GetRegistrationByKey must not be nil")
	}
	sha, err := core.KeyDigestB64(key.Key)
	if err != nil {
		return core.Registration{}, err
	}
	model, err := selectRegistration(ssa.dbMap.WithContext(ctx), query, sha)
	if db.IsNoRows(err) {
		return core.Registration{}, berrors.NotFoundError("no registrations with public key sha256 %q", sha)
	}
	if err != nil {
		return core.Registration{}, err
	}

	return modelToRegistration(model)
}

// incrementIP returns a copy of `ip` incremented at a bit index `index`,
// or in other words the first IP of the next highest subnet given a mask of
// length `index`.
// In order to easily account for overflow, we treat ip as a big.Int and add to
// it. If the increment overflows the max size of a net.IP, return the highest
// possible net.IP.
func incrementIP(ip net.IP, index int) net.IP {
	bigInt := new(big.Int)
	bigInt.SetBytes([]byte(ip))
	incr := new(big.Int).Lsh(big.NewInt(1), 128-uint(index))
	bigInt.Add(bigInt, incr)
	// bigInt.Bytes can be shorter than 16 bytes, so stick it into a
	// full-sized net.IP.
	resultBytes := bigInt.Bytes()
	if len(resultBytes) > 16 {
		return net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	}
	result := make(net.IP, 16)
	copy(result[16-len(resultBytes):], resultBytes)
	return result
}

// ipRange returns a range of IP addresses suitable for querying MySQL for the
// purpose of rate limiting using a range that is inclusive on the lower end and
// exclusive at the higher end. If ip is an IPv4 address, it returns that address,
// plus the one immediately higher than it. If ip is an IPv6 address, it applies
// a /48 mask to it and returns the lowest IP in the resulting network, and the
// first IP outside of the resulting network.
func ipRange(ip net.IP) (net.IP, net.IP) {
	ip = ip.To16()
	// For IPv6, match on a certain subnet range, since one person can commonly
	// have an entire /48 to themselves.
	maskLength := 48
	// For IPv4 addresses, do a match on exact address, so begin = ip and end =
	// next higher IP.
	if ip.To4() != nil {
		maskLength = 128
	}

	mask := net.CIDRMask(maskLength, 128)
	begin := ip.Mask(mask)
	end := incrementIP(begin, maskLength)

	return begin, end
}

// CountRegistrationsByIP returns the number of registrations created in the
// time range for a single IP address.
func (ssa *SQLStorageAuthority) CountRegistrationsByIP(ctx context.Context, ip net.IP, earliest time.Time, latest time.Time) (int, error) {
	var count int64
	err := ssa.dbMap.WithContext(ctx).SelectOne(
		&count,
		`SELECT COUNT(1) FROM registrations
		 WHERE
		 initialIP = :ip AND
		 :earliest < createdAt AND
		 createdAt <= :latest`,
		map[string]interface{}{
			"ip":       []byte(ip),
			"earliest": earliest,
			"latest":   latest,
		})
	if err != nil {
		return -1, err
	}
	return int(count), nil
}

// CountRegistrationsByIPRange returns the number of registrations created in
// the time range in an IP range. For IPv4 addresses, that range is limited to
// the single IP. For IPv6 addresses, that range is a /48, since it's not
// uncommon for one person to have a /48 to themselves.
func (ssa *SQLStorageAuthority) CountRegistrationsByIPRange(ctx context.Context, ip net.IP, earliest time.Time, latest time.Time) (int, error) {
	var count int64
	beginIP, endIP := ipRange(ip)
	err := ssa.dbMap.WithContext(ctx).SelectOne(
		&count,
		`SELECT COUNT(1) FROM registrations
		 WHERE
		 :beginIP <= initialIP AND
		 initialIP < :endIP AND
		 :earliest < createdAt AND
		 createdAt <= :latest`,
		map[string]interface{}{
			"earliest": earliest,
			"latest":   latest,
			"beginIP":  []byte(beginIP),
			"endIP":    []byte(endIP),
		})
	if err != nil {
		return -1, err
	}
	return int(count), nil
}

// CountCertificatesByNames counts, for each input domain, the number of
// certificates issued in the given time range for that domain and its
// subdomains. It returns a map from domains to counts, which is guaranteed to
// contain an entry for each input domain, so long as err is nil.
// Queries will be run in parallel. If any of them error, only one error will
// be returned.
func (ssa *SQLStorageAuthority) CountCertificatesByNames(ctx context.Context, domains []string, earliest, latest time.Time) ([]*sapb.CountByNames_MapElement, error) {
	work := make(chan string, len(domains))
	type result struct {
		err    error
		count  int
		domain string
	}
	results := make(chan result, len(domains))
	for _, domain := range domains {
		work <- domain
	}
	close(work)
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// We may perform up to 100 queries, depending on what's in the certificate
	// request. Parallelize them so we don't hit our timeout, but limit the
	// parallelism so we don't consume too many threads on the database.
	for i := 0; i < ssa.parallelismPerRPC; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range work {
				select {
				case <-ctx.Done():
					results <- result{err: ctx.Err()}
					return
				default:
				}
				currentCount, err := ssa.countCertificatesByName(
					ssa.dbMap.WithContext(ctx), domain, earliest, latest)
				if err != nil {
					results <- result{err: err}
					// Skip any further work
					cancel()
					return
				}
				results <- result{
					count:  currentCount,
					domain: domain,
				}
			}
		}()
	}
	wg.Wait()
	close(results)
	var ret []*sapb.CountByNames_MapElement
	for r := range results {
		if r.err != nil {
			return nil, r.err
		}
		name := string(r.domain)
		pbCount := int64(r.count)
		ret = append(ret, &sapb.CountByNames_MapElement{
			Name:  &name,
			Count: &pbCount,
		})
	}
	return ret, nil
}

func ReverseName(domain string) string {
	labels := strings.Split(domain, ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return strings.Join(labels, ".")
}

// GetCertificate takes a serial number and returns the corresponding
// certificate, or error if it does not exist.
func (ssa *SQLStorageAuthority) GetCertificate(ctx context.Context, serial string) (core.Certificate, error) {
	if !core.ValidSerial(serial) {
		err := fmt.Errorf("Invalid certificate serial %s", serial)
		return core.Certificate{}, err
	}

	cert, err := SelectCertificate(ssa.dbMap.WithContext(ctx), serial)
	if db.IsNoRows(err) {
		return core.Certificate{}, berrors.NotFoundError("certificate with serial %q not found", serial)
	}
	if err != nil {
		return core.Certificate{}, err
	}
	return cert, err
}

// GetCertificateStatus takes a hexadecimal string representing the full 128-bit serial
// number of a certificate and returns data about that certificate's current
// validity.
func (ssa *SQLStorageAuthority) GetCertificateStatus(ctx context.Context, serial string) (core.CertificateStatus, error) {
	if !core.ValidSerial(serial) {
		err := fmt.Errorf("Invalid certificate serial %s", serial)
		return core.CertificateStatus{}, err
	}

	certStatus, err := SelectCertificateStatus(ssa.dbMap.WithContext(ctx), serial)
	if err != nil {
		return core.CertificateStatus{}, err
	}

	return certStatus, nil
}

// NewRegistration stores a new Registration
func (ssa *SQLStorageAuthority) NewRegistration(ctx context.Context, reg core.Registration) (core.Registration, error) {
	reg.CreatedAt = ssa.clk.Now()
	rm, err := registrationToModel(&reg)
	if err != nil {
		return reg, err
	}
	err = ssa.dbMap.WithContext(ctx).Insert(rm)
	if err != nil {
		if db.IsDuplicate(err) {
			// duplicate entry error can only happen when jwk_sha256 collides, indicate
			// to caller that the provided key is already in use
			return reg, berrors.DuplicateError("key is already in use for a different account")
		}
		return reg, err
	}
	return modelToRegistration(rm)
}

// UpdateRegistration stores an updated Registration
func (ssa *SQLStorageAuthority) UpdateRegistration(ctx context.Context, reg core.Registration) error {
	const query = "WHERE id = ?"
	model, err := selectRegistration(ssa.dbMap.WithContext(ctx), query, reg.ID)
	if err != nil {
		if db.IsNoRows(err) {
			return berrors.NotFoundError("registration with ID '%d' not found", reg.ID)
		}
		return err
	}

	updatedRegModel, err := registrationToModel(&reg)
	if err != nil {
		return err
	}

	// Copy the existing registration model's LockCol to the new updated
	// registration model's LockCol
	updatedRegModel.LockCol = model.LockCol
	n, err := ssa.dbMap.WithContext(ctx).Update(updatedRegModel)
	if err != nil {
		if db.IsDuplicate(err) {
			// duplicate entry error can only happen when jwk_sha256 collides, indicate
			// to caller that the provided key is already in use
			return berrors.DuplicateError("key is already in use for a different account")
		}
		return err
	}
	if n == 0 {
		return berrors.NotFoundError("registration with ID '%d' not found", reg.ID)
	}

	return nil
}

// AddCertificate stores an issued certificate and returns the digest as
// a string, or an error if any occurred.
func (ssa *SQLStorageAuthority) AddCertificate(
	ctx context.Context,
	certDER []byte,
	regID int64,
	ocspResponse []byte,
	issued *time.Time) (string, error) {
	parsedCertificate, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", err
	}
	digest := core.Fingerprint256(certDER)
	serial := core.SerialToString(parsedCertificate.SerialNumber)

	cert := &core.Certificate{
		RegistrationID: regID,
		Serial:         serial,
		Digest:         digest,
		DER:            certDER,
		Issued:         *issued,
		Expires:        parsedCertificate.NotAfter,
	}

	isRenewalRaw, overallError := db.WithTransaction(ctx, ssa.dbMap, func(txWithCtx db.Executor) (interface{}, error) {
		// Save the final certificate
		err = txWithCtx.Insert(cert)
		if err != nil {
			if db.IsDuplicate(err) {
				return nil, berrors.DuplicateError("cannot add a duplicate cert")
			}
			return nil, err
		}

		// NOTE(@cpu): When we collect up names to check if an FQDN set exists (e.g.
		// that it is a renewal) we use just the DNSNames from the certificate and
		// ignore the Subject Common Name (if any). This is a safe assumption because
		// if a certificate we issued were to have a Subj. CN not present as a SAN it
		// would be a misissuance and miscalculating whether the cert is a renewal or
		// not for the purpose of rate limiting is the least of our troubles.
		isRenewal, err := ssa.checkFQDNSetExists(
			txWithCtx.SelectOne,
			parsedCertificate.DNSNames)
		if err != nil {
			return nil, err
		}

		return isRenewal, err
	})
	if overallError != nil {
		return "", overallError
	}

	// Recast the interface{} return from db.WithTransaction as a bool, returning
	// an error if we can't.
	var isRenewal bool
	if boolVal, ok := isRenewalRaw.(bool); !ok {
		return "", fmt.Errorf(
			"AddCertificate db.WithTransaction returned %T out var, expected bool",
			isRenewalRaw)
	} else {
		isRenewal = boolVal
	}

	// In a separate transaction perform the work required to update tables used
	// for rate limits. Since the effects of failing these writes is slight
	// miscalculation of rate limits we choose to not fail the AddCertificate
	// operation if the rate limit update transaction fails.
	_, rlTransactionErr := db.WithTransaction(ctx, ssa.dbMap, func(txWithCtx db.Executor) (interface{}, error) {
		// Add to the rate limit table, but only for new certificates. Renewals
		// don't count against the certificatesPerName limit.
		if !isRenewal {
			timeToTheHour := parsedCertificate.NotBefore.Round(time.Hour)
			if err := ssa.addCertificatesPerName(ctx, txWithCtx, parsedCertificate.DNSNames, timeToTheHour); err != nil {
				return nil, err
			}
		}

		// Update the FQDN sets now that there is a final certificate to ensure rate
		// limits are calculated correctly.
		if err := addFQDNSet(
			txWithCtx,
			parsedCertificate.DNSNames,
			core.SerialToString(parsedCertificate.SerialNumber),
			parsedCertificate.NotBefore,
			parsedCertificate.NotAfter,
		); err != nil {
			return nil, err
		}

		return nil, nil
	})
	// If the ratelimit transaction failed increment a stat and log a warning
	// but don't return an error from AddCertificate.
	if rlTransactionErr != nil {
		ssa.rateLimitWriteErrors.Inc()
		ssa.log.AuditErrf("failed AddCertificate ratelimit update transaction: %v", rlTransactionErr)
	}

	return digest, nil
}

func (ssa *SQLStorageAuthority) CountOrders(ctx context.Context, acctID int64, earliest, latest time.Time) (int, error) {
	if features.Enabled(features.FasterNewOrdersRateLimit) {
		return countNewOrders(ctx, ssa.dbMap, acctID, earliest, latest)
	}

	var count int
	err := ssa.dbMap.WithContext(ctx).SelectOne(&count,
		`SELECT count(1) FROM orders
		WHERE registrationID = :acctID AND
		created >= :windowLeft AND
		created < :windowRight`,
		map[string]interface{}{
			"acctID":      acctID,
			"windowLeft":  earliest,
			"windowRight": latest,
		})
	if err != nil {
		return 0, err
	}
	return count, nil
}

func hashNames(names []string) []byte {
	names = core.UniqueLowerNames(names)
	hash := sha256.Sum256([]byte(strings.Join(names, ",")))
	return hash[:]
}

func addFQDNSet(db db.Inserter, names []string, serial string, issued time.Time, expires time.Time) error {
	return db.Insert(&core.FQDNSet{
		SetHash: hashNames(names),
		Serial:  serial,
		Issued:  issued,
		Expires: expires,
	})
}

// addOrderFQDNSet creates a new OrderFQDNSet row using the provided
// information. This function accepts a transaction so that the orderFqdnSet
// addition can take place within the order addition transaction. The caller is
// required to rollback the transaction if an error is returned.
func addOrderFQDNSet(
	db db.Inserter,
	names []string,
	orderID int64,
	regID int64,
	expires time.Time) error {
	return db.Insert(&orderFQDNSet{
		SetHash:        hashNames(names),
		OrderID:        orderID,
		RegistrationID: regID,
		Expires:        expires,
	})
}

// deleteOrderFQDNSet deletes a OrderFQDNSet row that matches the provided
// orderID. This function accepts a transaction so that the deletion can
// take place within the finalization transaction. The caller is required to
// rollback the transaction if an error is returned.
func deleteOrderFQDNSet(
	db db.Execer,
	orderID int64) error {

	result, err := db.Exec(`
	  DELETE FROM orderFqdnSets
		WHERE orderID = ?`,
		orderID)
	if err != nil {
		return err
	}
	rowsDeleted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	// We always expect there to be an order FQDN set row for each
	// pending/processing order that is being finalized. If there isn't one then
	// something is amiss and should be raised as an internal server error
	if rowsDeleted == 0 {
		return berrors.InternalServerError("No orderFQDNSet exists to delete")
	}
	return nil
}

func addIssuedNames(db db.Execer, cert *x509.Certificate, isRenewal bool) error {
	if len(cert.DNSNames) == 0 {
		return berrors.InternalServerError("certificate has no DNSNames")
	}
	var qmarks []string
	var values []interface{}
	for _, name := range cert.DNSNames {
		values = append(values,
			ReverseName(name),
			core.SerialToString(cert.SerialNumber),
			cert.NotBefore,
			isRenewal)
		qmarks = append(qmarks, "(?, ?, ?, ?)")
	}
	query := `INSERT INTO issuedNames (reversedName, serial, notBefore, renewal) VALUES ` + strings.Join(qmarks, ", ") + `;`
	_, err := db.Exec(query, values...)
	return err
}

// CountFQDNSets returns the number of sets with hash |setHash| within the window
// |window|
func (ssa *SQLStorageAuthority) CountFQDNSets(ctx context.Context, window time.Duration, names []string) (int64, error) {
	var count int64
	err := ssa.dbMap.WithContext(ctx).SelectOne(
		&count,
		`SELECT COUNT(1) FROM fqdnSets
		WHERE setHash = ?
		AND issued > ?`,
		hashNames(names),
		ssa.clk.Now().Add(-window),
	)
	return count, err
}

// setHash is a []byte representing the hash of an FQDN Set
type setHash []byte

// getFQDNSetsBySerials finds the setHashes corresponding to a set of
// certificate serials. These serials can be used to check whether any
// certificates have been issued for the same set of names previously.
func (ssa *SQLStorageAuthority) getFQDNSetsBySerials(
	dbMap db.Selector,
	serials []string,
) ([]setHash, error) {
	var fqdnSets []setHash

	// It is unexpected that this function would be called with no serials
	if len(serials) == 0 {
		err := fmt.Errorf("getFQDNSetsBySerials called with no serials")
		ssa.log.AuditErr(err.Error())
		return nil, err
	}

	qmarks := make([]string, len(serials))
	params := make([]interface{}, len(serials))
	for i, serial := range serials {
		params[i] = serial
		qmarks[i] = "?"
	}
	query := "SELECT setHash FROM fqdnSets " +
		"WHERE serial IN (" + strings.Join(qmarks, ",") + ")"
	_, err := dbMap.Select(
		&fqdnSets,
		query,
		params...)

	if err != nil {
		return nil, err
	}

	// The serials existed when we found them in issuedNames, they should continue
	// to exist here. Otherwise an internal consistency violation occurred and
	// needs to be audit logged
	if db.IsNoRows(err) {
		err := fmt.Errorf("getFQDNSetsBySerials returned no rows - internal consistency violation")
		ssa.log.AuditErr(err.Error())
		return nil, err
	}
	return fqdnSets, nil
}

// getNewIssuancesByFQDNSet returns a count of new issuances (renewals are not
// included) for a given slice of fqdnSets that occurred after the earliest
// parameter.
func (ssa *SQLStorageAuthority) getNewIssuancesByFQDNSet(
	dbMap db.Selector,
	fqdnSets []setHash,
	earliest time.Time,
) (int, error) {
	var results []struct {
		Serial  string
		SetHash setHash
		Issued  time.Time
	}

	qmarks := make([]string, len(fqdnSets))
	params := make([]interface{}, len(fqdnSets))
	for i, setHash := range fqdnSets {
		// We have to cast the setHash back to []byte here since the sql package
		// isn't able to convert `sa.setHash` for the parameter value itself
		params[i] = []byte(setHash)
		qmarks[i] = "?"
	}

	query := "SELECT serial, setHash, issued FROM fqdnSets " +
		"WHERE setHash IN (" + strings.Join(qmarks, ",") + ") " +
		"ORDER BY setHash, issued"

	// First, find the serial, sethash and issued date from the fqdnSets table for
	// the given fqdn set hashes
	_, err := dbMap.Select(
		&results,
		query,
		params...)
	if err != nil {
		// If there are no results we have encountered a major error and
		// should loudly complain
		if db.IsNoRows(err) {
			ssa.log.AuditErrf("Found no results from fqdnSets for setHashes known to exist: %#v", fqdnSets)
			return 0, err
		}
		return -1, err
	}

	processedSetHashes := make(map[string]bool)
	issuanceCount := 0
	// Loop through each set hash result, counting issuances per unique set hash
	// that are within the window specified by the earliest parameter
	for _, result := range results {
		key := string(result.SetHash)
		// Skip set hashes that we have already processed - we only care about the
		// first issuance
		if processedSetHashes[key] {
			continue
		}

		// If the issued date is before our earliest cutoff then skip it
		if result.Issued.Before(earliest) {
			continue
		}

		// Otherwise note the issuance and mark the set hash as processed
		issuanceCount++
		processedSetHashes[key] = true
	}

	// Return the count of how many non-renewal issuances there were
	return issuanceCount, nil
}

// FQDNSetExists returns a bool indicating if one or more FQDN sets |names|
// exists in the database
func (ssa *SQLStorageAuthority) FQDNSetExists(ctx context.Context, names []string) (bool, error) {
	exists, err := ssa.checkFQDNSetExists(
		ssa.dbMap.WithContext(ctx).SelectOne,
		names)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// oneSelectorFunc is a func type that matches both gorp.Transaction.SelectOne
// and gorp.DbMap.SelectOne.
type oneSelectorFunc func(holder interface{}, query string, args ...interface{}) error

// checkFQDNSetExists uses the given oneSelectorFunc to check whether an fqdnSet
// for the given names exists.
func (ssa *SQLStorageAuthority) checkFQDNSetExists(selector oneSelectorFunc, names []string) (bool, error) {
	var count int64
	err := selector(
		&count,
		`SELECT COUNT(1) FROM fqdnSets
		WHERE setHash = ?
		LIMIT 1`,
		hashNames(names),
	)
	return count > 0, err
}

// PreviousCertificateExists returns true iff there was at least one certificate
// issued with the provided domain name, and the most recent such certificate
// was issued by the provided registration ID. This method is currently only
// used to determine if a certificate has previously been issued for a given
// domain name in order to determine if validations should be allowed during
// the v1 API shutoff.
func (ssa *SQLStorageAuthority) PreviousCertificateExists(
	ctx context.Context,
	req *sapb.PreviousCertificateExistsRequest,
) (*sapb.Exists, error) {
	t := true
	exists := &sapb.Exists{Exists: &t}

	f := false
	notExists := &sapb.Exists{Exists: &f}

	// Find the most recently issued certificate containing this domain name.
	var serial string
	err := ssa.dbMap.WithContext(ctx).SelectOne(
		&serial,
		`SELECT serial FROM issuedNames
		WHERE reversedName = ?
		ORDER BY notBefore DESC
		LIMIT 1`,
		ReverseName(*req.Domain),
	)
	if err != nil {
		if db.IsNoRows(err) {
			return notExists, nil
		}
		return nil, err
	}

	// Check whether that certificate was issued to the specified account.
	var count int
	err = ssa.dbMap.WithContext(ctx).SelectOne(
		&count,
		`SELECT COUNT(1) FROM certificates
		WHERE serial = ?
		AND registrationID = ?`,
		serial,
		*req.RegID,
	)
	if err != nil {
		// If no rows found, that means the certificate we found in issuedNames wasn't
		// issued by the registration ID we are checking right now, but is not an
		// error.
		if db.IsNoRows(err) {
			return notExists, nil
		}
		return nil, err
	}
	if count > 0 {
		return exists, nil
	}
	return notExists, nil
}

// DeactivateRegistration deactivates a currently valid registration
func (ssa *SQLStorageAuthority) DeactivateRegistration(ctx context.Context, id int64) error {
	_, err := ssa.dbMap.WithContext(ctx).Exec(
		"UPDATE registrations SET status = ? WHERE status = ? AND id = ?",
		string(core.StatusDeactivated),
		string(core.StatusValid),
		id,
	)
	return err
}

// DeactivateAuthorization2 deactivates a currently valid or pending authorization.
// This method is intended to deprecate DeactivateAuthorization.
func (ssa *SQLStorageAuthority) DeactivateAuthorization2(ctx context.Context, req *sapb.AuthorizationID2) (*corepb.Empty, error) {
	_, err := ssa.dbMap.Exec(
		`UPDATE authz2 SET status = :deactivated WHERE id = :id and status IN (:valid,:pending)`,
		map[string]interface{}{
			"deactivated": statusUint(core.StatusDeactivated),
			"id":          *req.Id,
			"valid":       statusUint(core.StatusValid),
			"pending":     statusUint(core.StatusPending),
		},
	)
	if err != nil {
		return nil, err
	}
	return &corepb.Empty{}, nil
}

// NewOrder adds a new v2 style order to the database
func (ssa *SQLStorageAuthority) NewOrder(ctx context.Context, req *corepb.Order) (*corepb.Order, error) {
	order := &orderModel{
		RegistrationID: *req.RegistrationID,
		Expires:        time.Unix(0, *req.Expires),
		Created:        ssa.clk.Now(),
	}

	output, overallError := db.WithTransaction(ctx, ssa.dbMap, func(txWithCtx db.Executor) (interface{}, error) {
		if err := txWithCtx.Insert(order); err != nil {
			return nil, err
		}

		for _, id := range req.V2Authorizations {
			otoa := &orderToAuthzModel{
				OrderID: order.ID,
				AuthzID: id,
			}
			if err := txWithCtx.Insert(otoa); err != nil {
				return nil, err
			}
		}

		for _, name := range req.Names {
			reqdName := &requestedNameModel{
				OrderID:      order.ID,
				ReversedName: ReverseName(name),
			}
			if err := txWithCtx.Insert(reqdName); err != nil {
				return nil, err
			}
		}

		// Add an FQDNSet entry for the order
		if err := addOrderFQDNSet(
			txWithCtx, req.Names, order.ID, order.RegistrationID, order.Expires); err != nil {
			return nil, err
		}

		if features.Enabled(features.FasterNewOrdersRateLimit) {
			// Increment the order creation count
			if err := addNewOrdersRateLimit(ctx, txWithCtx, *req.RegistrationID, ssa.clk.Now().Truncate(time.Minute)); err != nil {
				return nil, err
			}
		}

		return req, nil
	})
	if overallError != nil {
		return nil, overallError
	}
	var outputOrder *corepb.Order
	var ok bool
	if outputOrder, ok = output.(*corepb.Order); !ok {
		return nil, fmt.Errorf("shouldn't happen: casting error in NewOrder")
	}
	// Update the output with the ID that the order received
	outputOrder.Id = &order.ID
	// Update the output with the created timestamp from the model
	createdTS := order.Created.UnixNano()
	outputOrder.Created = &createdTS
	// A new order is never processing because it can't have been finalized yet
	processingStatus := false
	outputOrder.BeganProcessing = &processingStatus

	// Calculate the order status before returning it. Since it may have reused all
	// valid authorizations the order may be "born" in a ready status.
	status, err := ssa.statusForOrder(ctx, outputOrder)
	if err != nil {
		return nil, err
	}
	outputOrder.Status = &status
	return outputOrder, nil
}

// SetOrderProcessing updates a provided *corepb.Order in pending status to be
// in processing status by updating the `beganProcessing` field of the
// corresponding Order table row in the DB.
func (ssa *SQLStorageAuthority) SetOrderProcessing(ctx context.Context, req *corepb.Order) error {
	_, overallError := db.WithTransaction(ctx, ssa.dbMap, func(txWithCtx db.Executor) (interface{}, error) {
		result, err := txWithCtx.Exec(`
		UPDATE orders
		SET beganProcessing = ?
		WHERE id = ?
		AND beganProcessing = ?`,
			true,
			*req.Id,
			false)
		if err != nil {
			return nil, berrors.InternalServerError("error updating order to beganProcessing status")
		}

		n, err := result.RowsAffected()
		if err != nil || n == 0 {
			return nil, berrors.OrderNotReadyError("Order was already processing. This may indicate your client finalized the same order multiple times, possibly due to a client bug.")
		}

		return nil, nil
	})
	return overallError
}

// SetOrderError updates a provided Order's error field.
func (ssa *SQLStorageAuthority) SetOrderError(ctx context.Context, order *corepb.Order) error {
	_, overallError := db.WithTransaction(ctx, ssa.dbMap, func(txWithCtx db.Executor) (interface{}, error) {
		om, err := orderToModel(order)
		if err != nil {
			return nil, err
		}

		result, err := txWithCtx.Exec(`
		UPDATE orders
		SET error = ?
		WHERE id = ?`,
			om.Error,
			om.ID)
		if err != nil {
			return nil, berrors.InternalServerError("error updating order error field")
		}

		n, err := result.RowsAffected()
		if err != nil || n == 0 {
			return nil, berrors.InternalServerError("no order updated with new error field")
		}

		return nil, nil
	})
	return overallError
}

// FinalizeOrder finalizes a provided *corepb.Order by persisting the
// CertificateSerial and a valid status to the database. No fields other than
// CertificateSerial and the order ID on the provided order are processed (e.g.
// this is not a generic update RPC).
func (ssa *SQLStorageAuthority) FinalizeOrder(ctx context.Context, req *corepb.Order) error {
	_, overallError := db.WithTransaction(ctx, ssa.dbMap, func(txWithCtx db.Executor) (interface{}, error) {
		result, err := txWithCtx.Exec(`
		UPDATE orders
		SET certificateSerial = ?
		WHERE id = ? AND
		beganProcessing = true`,
			*req.CertificateSerial,
			*req.Id)
		if err != nil {
			return nil, berrors.InternalServerError("error updating order for finalization")
		}

		n, err := result.RowsAffected()
		if err != nil || n == 0 {
			return nil, berrors.InternalServerError("no order updated for finalization")
		}

		// Delete the orderFQDNSet row for the order now that it has been finalized.
		// We use this table for order reuse and should not reuse a finalized order.
		if err := deleteOrderFQDNSet(txWithCtx, *req.Id); err != nil {
			return nil, err
		}

		return nil, nil
	})
	return overallError
}

// authzForOrder retrieves the authorization IDs for an order. It returns these
// IDs in two slices: one for v1 style authorizations, and another for
// v2 style authorizations.
func (ssa *SQLStorageAuthority) authzForOrder(ctx context.Context, orderID int64) ([]int64, error) {
	var v2IDs []int64
	_, err := ssa.dbMap.WithContext(ctx).Select(
		&v2IDs,
		"SELECT authzID FROM orderToAuthz2 WHERE orderID = ?",
		orderID,
	)
	return v2IDs, err
}

// namesForOrder finds all of the requested names associated with an order. The
// names are returned in their reversed form (see `sa.ReverseName`).
func (ssa *SQLStorageAuthority) namesForOrder(ctx context.Context, orderID int64) ([]string, error) {
	var reversedNames []string
	_, err := ssa.dbMap.WithContext(ctx).Select(
		&reversedNames,
		`SELECT reversedName
	   FROM requestedNames
	   WHERE orderID = ?`,
		orderID)
	if err != nil {
		return nil, err
	}
	return reversedNames, nil
}

// GetOrder is used to retrieve an already existing order object
func (ssa *SQLStorageAuthority) GetOrder(ctx context.Context, req *sapb.OrderRequest) (*corepb.Order, error) {
	omObj, err := ssa.dbMap.WithContext(ctx).Get(orderModel{}, *req.Id)
	if err != nil {
		if db.IsNoRows(err) {
			return nil, berrors.NotFoundError("no order found for ID %d", *req.Id)
		}
		return nil, err
	}
	if omObj == nil {
		return nil, berrors.NotFoundError("no order found for ID %d", *req.Id)
	}
	order, err := modelToOrder(omObj.(*orderModel))
	if err != nil {
		return nil, err
	}
	orderExp := time.Unix(0, *order.Expires)
	if orderExp.Before(ssa.clk.Now()) {
		return nil, berrors.NotFoundError("no order found for ID %d", *req.Id)
	}

	v2AuthzIDs, err := ssa.authzForOrder(ctx, *order.Id)
	if err != nil {
		return nil, err
	}
	order.V2Authorizations = v2AuthzIDs

	names, err := ssa.namesForOrder(ctx, *order.Id)
	if err != nil {
		return nil, err
	}
	// The requested names are stored reversed to improve indexing performance. We
	// need to reverse the reversed names here before giving them back to the
	// caller.
	reversedNames := make([]string, len(names))
	for i, n := range names {
		reversedNames[i] = ReverseName(n)
	}
	order.Names = reversedNames

	// Calculate the status for the order
	status, err := ssa.statusForOrder(ctx, order)
	if err != nil {
		return nil, err
	}
	order.Status = &status

	return order, nil
}

// statusForOrder examines the status of a provided order's authorizations to
// determine what the overall status of the order should be. In summary:
//   * If the order has an error, the order is invalid
//   * If any of the order's authorizations are invalid, the order is invalid.
//   * If any of the order's authorizations are expired, the order is invalid.
//   * If any of the order's authorizations are deactivated, the order is invalid.
//   * If any of the order's authorizations are pending, the order is pending.
//   * If all of the order's authorizations are valid, and there is
//     a certificate serial, the order is valid.
//   * If all of the order's authorizations are valid, and we have began
//     processing, but there is no certificate serial, the order is processing.
//   * If all of the order's authorizations are valid, and we haven't begun
//     processing, then the order is status ready.
// An error is returned for any other case.
//
// While transitioning between the v1 and v2 authorization storage formats this method
// needs to lookup authorizations using both the authz/pendingAuthorizations and authz2
// tables. Since, if there are any v2 authorizations, we already have their IDs we don't
// need to consult the orderToAuthz2 table a second time. We cannot do this as easily
// for the v1 authorizations as their IDs can refer to one of two tables, whereas all
// v2 authorizations exist in a single table.
func (ssa *SQLStorageAuthority) statusForOrder(ctx context.Context, order *corepb.Order) (string, error) {
	// Without any further work we know an order with an error is invalid
	if order.Error != nil {
		return string(core.StatusInvalid), nil
	}

	// If the order is expired the status is invalid and we don't need to get
	// order authorizations. Its important to exit early in this case because an
	// order that references an expired authorization will be itself have been
	// expired (because we match the order expiry to the associated authz expiries
	// in ra.NewOrder), and expired authorizations may be purged from the DB.
	// Because of this purging fetching the authz's for an expired order may
	// return fewer authz objects than expected, triggering a 500 error response.
	orderExpiry := time.Unix(0, *order.Expires)
	if orderExpiry.Before(ssa.clk.Now()) {
		return string(core.StatusInvalid), nil
	}

	// Get the full Authorization objects for the order
	authzValidityInfo, err := ssa.getAuthorizationStatuses(ctx, order.V2Authorizations)
	// If there was an error getting the authorizations, return it immediately
	if err != nil {
		return "", err
	}

	// If getAuthorizationStatuses returned a different number of authorization
	// objects than the order's slice of authorization IDs something has gone
	// wrong worth raising an internal error about.
	if len(authzValidityInfo) != len(order.V2Authorizations) {
		return "", berrors.InternalServerError(
			"getAuthorizationStatuses returned the wrong number of authorization statuses "+
				"(%d vs expected %d) for order %d",
			len(authzValidityInfo), len(order.V2Authorizations), *order.Id)
	}

	// Keep a count of the authorizations seen
	invalidAuthzs := 0
	expiredAuthzs := 0
	deactivatedAuthzs := 0
	pendingAuthzs := 0
	validAuthzs := 0

	// Loop over each of the order's authorization objects to examine the authz status
	for _, info := range authzValidityInfo {
		switch core.AcmeStatus(info.Status) {
		case core.StatusInvalid:
			invalidAuthzs++
		case core.StatusDeactivated:
			deactivatedAuthzs++
		case core.StatusPending:
			pendingAuthzs++
		case core.StatusValid:
			validAuthzs++
		default:
			return "", berrors.InternalServerError(
				"Order is in an invalid state. Authz has invalid status %s",
				info.Status)
		}
		if info.Expires.Before(ssa.clk.Now()) {
			expiredAuthzs++
		}
	}

	// An order is invalid if **any** of its authzs are invalid, deactivated,
	// or expired, see https://tools.ietf.org/html/rfc8555#section-7.1.6
	if invalidAuthzs > 0 ||
		expiredAuthzs > 0 ||
		deactivatedAuthzs > 0 {
		return string(core.StatusInvalid), nil
	}
	// An order is pending if **any** of its authzs are pending
	if pendingAuthzs > 0 {
		return string(core.StatusPending), nil
	}

	// An order is fully authorized if it has valid authzs for each of the order
	// names
	fullyAuthorized := len(order.Names) == validAuthzs

	// If the order isn't fully authorized we've encountered an internal error:
	// Above we checked for any invalid or pending authzs and should have returned
	// early. Somehow we made it this far but also don't have the correct number
	// of valid authzs.
	if !fullyAuthorized {
		return "", berrors.InternalServerError(
			"Order has the incorrect number of valid authorizations & no pending, " +
				"deactivated or invalid authorizations")
	}

	// If the order is fully authorized and the certificate serial is set then the
	// order is valid
	if fullyAuthorized && order.CertificateSerial != nil && *order.CertificateSerial != "" {
		return string(core.StatusValid), nil
	}

	// If the order is fully authorized, and we have began processing it, then the
	// order is processing.
	if fullyAuthorized && order.BeganProcessing != nil && *order.BeganProcessing {
		return string(core.StatusProcessing), nil
	}

	if fullyAuthorized && order.BeganProcessing != nil && !*order.BeganProcessing {
		return string(core.StatusReady), nil
	}

	return "", berrors.InternalServerError(
		"Order %d is in an invalid state. No state known for this order's "+
			"authorizations", *order.Id)
}

type authzValidity struct {
	Status  string
	Expires time.Time
}

func (ssa *SQLStorageAuthority) getAuthorizationStatuses(ctx context.Context, ids []int64) ([]authzValidity, error) {
	var qmarks []string
	var params []interface{}
	for _, id := range ids {
		qmarks = append(qmarks, "?")
		params = append(params, id)
	}
	var validityInfo []struct {
		Status  uint8
		Expires time.Time
	}
	_, err := ssa.dbMap.WithContext(ctx).Select(
		&validityInfo,
		fmt.Sprintf("SELECT status, expires FROM authz2 WHERE id IN (%s)", strings.Join(qmarks, ",")),
		params...,
	)
	if err != nil {
		return nil, err
	}

	allAuthzValidity := make([]authzValidity, len(validityInfo))
	for i, info := range validityInfo {
		allAuthzValidity[i] = authzValidity{
			Status:  uintToStatus[info.Status],
			Expires: info.Expires,
		}
	}
	return allAuthzValidity, nil
}

// GetOrderForNames tries to find a **pending** or **ready** order with the
// exact set of names requested, associated with the given accountID. Only
// unexpired orders are considered. If no order meeting these requirements is
// found a nil corepb.Order pointer is returned.
func (ssa *SQLStorageAuthority) GetOrderForNames(
	ctx context.Context,
	req *sapb.GetOrderForNamesRequest) (*corepb.Order, error) {

	// Hash the names requested for lookup in the orderFqdnSets table
	fqdnHash := hashNames(req.Names)

	// Find a possibly-suitable order. We don't include the account ID or order
	// status in this query because there's no index that includes those, so
	// including them could require the DB to scan extra rows.
	// Instead, we select one unexpired order that matches the fqdnSet. If
	// that order doesn't match the account ID or status we need, just return
	// nothing. We use `ORDER BY expires ASC` because the index on
	// (setHash, expires) is in ASC order. DESC would be slightly nicer from a
	// user experience perspective but would be slow when there are many entries
	// to sort.
	// This approach works fine because in most cases there's only one account
	// issuing for a given name. If there are other accounts issuing for the same
	// name, it just means order reuse happens less often.
	var result struct {
		OrderID        int64
		RegistrationID int64
	}
	var err error
	err = ssa.dbMap.WithContext(ctx).SelectOne(&result, `
					SELECT orderID, registrationID
					FROM orderFqdnSets
					WHERE setHash = ?
					AND expires > ?
					ORDER BY expires ASC
					LIMIT 1`,
		fqdnHash, ssa.clk.Now())

	if db.IsNoRows(err) {
		return nil, berrors.NotFoundError("no order matching request found")
	} else if err != nil {
		return nil, err
	}

	if result.RegistrationID != *req.AcctID {
		return nil, berrors.NotFoundError("no order matching request found")
	}

	// Get the order
	order, err := ssa.GetOrder(ctx, &sapb.OrderRequest{Id: &result.OrderID})
	if err != nil {
		return nil, err
	}
	// Only return a pending or ready order
	if *order.Status != string(core.StatusPending) &&
		*order.Status != string(core.StatusReady) {
		return nil, berrors.NotFoundError("no order matching request found")
	}
	return order, nil
}

func AuthzMapToPB(m map[string]*core.Authorization) (*sapb.Authorizations, error) {
	resp := &sapb.Authorizations{}
	for k, v := range m {
		authzPB, err := bgrpc.AuthzToPB(*v)
		if err != nil {
			return nil, err
		}
		// Make a copy of k because it will be reassigned with each loop.
		kCopy := k
		resp.Authz = append(resp.Authz, &sapb.Authorizations_MapElement{Domain: &kCopy, Authz: authzPB})
	}
	return resp, nil
}

// NewAuthorizations2 adds a set of new style authorizations to the database and returns
// either the IDs of the authorizations or an error. It will only process corepb.Authorization
// objects if the V2 field is set. This method is intended to deprecate AddPendingAuthorizations
func (ssa *SQLStorageAuthority) NewAuthorizations2(ctx context.Context, req *sapb.AddPendingAuthorizationsRequest) (*sapb.Authorization2IDs, error) {
	ids := &sapb.Authorization2IDs{}
	for _, authz := range req.Authz {
		if *authz.Status != string(core.StatusPending) {
			return nil, berrors.InternalServerError("authorization must be pending")
		}
		am, err := authzPBToModel(authz)
		if err != nil {
			return nil, err
		}
		err = ssa.dbMap.Insert(am)
		if err != nil {
			return nil, err
		}
		ids.Ids = append(ids.Ids, am.ID)
	}
	return ids, nil
}

// GetAuthorization2 returns the authz2 style authorization identified by the provided ID or an error.
// If no authorization is found matching the ID a berrors.NotFound type error is returned. This method
// is intended to deprecate GetAuthorization.
func (ssa *SQLStorageAuthority) GetAuthorization2(ctx context.Context, id *sapb.AuthorizationID2) (*corepb.Authorization, error) {
	obj, err := ssa.dbMap.Get(authzModel{}, *id.Id)
	if err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, berrors.NotFoundError("authorization %d not found", *id.Id)
	}
	return modelToAuthzPB(*(obj.(*authzModel)))
}

// authzModelMapToPB converts a mapping of domain name to authzModels into a
// protobuf authorizations map
func authzModelMapToPB(m map[string]authzModel) (*sapb.Authorizations, error) {
	resp := &sapb.Authorizations{}
	for k, v := range m {
		// Make a copy of k because it will be reassigned with each loop.
		kCopy := k
		authzPB, err := modelToAuthzPB(v)
		if err != nil {
			return nil, err
		}
		resp.Authz = append(resp.Authz, &sapb.Authorizations_MapElement{Domain: &kCopy, Authz: authzPB})
	}
	return resp, nil
}

// GetAuthorizations2 returns any valid or pending authorizations that exist for the list of domains
// provided. If both a valid and pending authorization exist only the valid one will be returned.
// This method will look in both the v2 and v1 authorizations tables for authorizations but will
// always prefer v2 authorizations. This method will only return authorizations created using the
// WFE v2 API (in GetAuthorizations this feature was, now somewhat confusingly, called RequireV2Authzs).
// This method is intended to deprecate GetAuthorizations. This method only supports DNS identifier types.
func (ssa *SQLStorageAuthority) GetAuthorizations2(ctx context.Context, req *sapb.GetAuthorizationsRequest) (*sapb.Authorizations, error) {
	var authzModels []authzModel
	params := []interface{}{
		*req.RegistrationID,
		statusUint(core.StatusValid),
		statusUint(core.StatusPending),
		time.Unix(0, *req.Now),
		identifierTypeToUint[string(identifier.DNS)],
	}
	qmarks := make([]string, len(req.Domains))
	for i, n := range req.Domains {
		qmarks[i] = "?"
		params = append(params, n)
	}
	var query string
	query = fmt.Sprintf(
		`SELECT %s FROM authz2
			WHERE registrationID = ? AND
			status IN (?,?) AND
			expires > ? AND
			identifierType = ? AND
			identifierValue IN (%s)`,
		authzFields,
		strings.Join(qmarks, ","),
	)
	_, err := ssa.dbMap.Select(
		&authzModels,
		query,
		params...,
	)
	if err != nil {
		return nil, err
	}

	if len(authzModels) == 0 {
		return &sapb.Authorizations{}, nil
	}

	// Previously we used a JOIN on the orderToAuthz2 table in order to make sure
	// we only returned authorizations created using the ACME v2 API. Each time an
	// order is created a pivot row (order ID + authz ID) is added to the
	// orderToAuthz2 table. If a large number of orders are created that all contain
	// the same authorization, due to reuse, then the JOINd query would return a full
	// authorization row for each entry in the orderToAuthz2 table with the authorization
	// ID.
	//
	// Instead we now filter out these authorizations by doing a second query against
	// the orderToAuthz2 table. Using this query still requires examining a large number
	// of rows, but because we don't need to construct a temporary table for the JOIN
	// and fill it with all the full authorization rows we should save resources.
	var ids []interface{}
	qmarks = make([]string, len(authzModels))
	for i, am := range authzModels {
		ids = append(ids, am.ID)
		qmarks[i] = "?"
	}
	var authzIDs []int64
	_, err = ssa.dbMap.Select(
		&authzIDs,
		fmt.Sprintf(`SELECT DISTINCT(authzID) FROM orderToAuthz2 WHERE authzID IN (%s)`, strings.Join(qmarks, ",")),
		ids...,
	)
	if err != nil {
		return nil, err
	}
	authzIDMap := map[int64]bool{}
	for _, id := range authzIDs {
		authzIDMap[id] = true
	}

	authzModelMap := make(map[string]authzModel)
	for _, am := range authzModels {
		// Anything not found in the ID map wasn't in the pivot table, meaning it
		// didn't correspond to an order, meaning it wasn't created with ACMEv2.
		// Don't return it for ACMEv2 requests.
		if _, present := authzIDMap[am.ID]; !present {
			continue
		}
		if existing, present := authzModelMap[am.IdentifierValue]; !present ||
			uintToStatus[existing.Status] == string(core.StatusPending) && uintToStatus[am.Status] == string(core.StatusValid) {
			authzModelMap[am.IdentifierValue] = am
		}
	}

	return authzModelMapToPB(authzModelMap)
}

// FinalizeAuthorization2 moves a pending authorization to either the valid or invalid status. If
// the authorization is being moved to invalid the validationError field must be set. If the
// authorization is being moved to valid the validationRecord and expires fields must be set.
// This method is intended to deprecate the FinalizeAuthorization method.
func (ssa *SQLStorageAuthority) FinalizeAuthorization2(ctx context.Context, req *sapb.FinalizeAuthorizationRequest) error {
	if *req.Status != string(core.StatusValid) && *req.Status != string(core.StatusInvalid) {
		return berrors.InternalServerError("authorization must have status valid or invalid")
	}
	query := `UPDATE authz2 SET
		status = :status,
		attempted = :attempted,
		validationRecord = :validationRecord,
		validationError = :validationError,
		expires = :expires
		WHERE id = :id AND status = :pending`
	var validationRecords []core.ValidationRecord
	for _, recordPB := range req.ValidationRecords {
		record, err := bgrpc.PBToValidationRecord(recordPB)
		if err != nil {
			return err
		}
		validationRecords = append(validationRecords, record)
	}
	vrJSON, err := json.Marshal(validationRecords)
	if err != nil {
		return err
	}
	var veJSON []byte
	if req.ValidationError != nil {
		validationError, err := bgrpc.PBToProblemDetails(req.ValidationError)
		if err != nil {
			return err
		}
		j, err := json.Marshal(validationError)
		if err != nil {
			return err
		}
		veJSON = j
	}
	params := map[string]interface{}{
		"status":           statusToUint[*req.Status],
		"attempted":        challTypeToUint[*req.Attempted],
		"validationRecord": vrJSON,
		"id":               *req.Id,
		"pending":          statusUint(core.StatusPending),
		"expires":          time.Unix(0, *req.Expires).UTC(),
		// if req.ValidationError is nil veJSON should also be nil
		// which should result in a NULL field
		"validationError": veJSON,
	}

	res, err := ssa.dbMap.Exec(query, params)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return berrors.NotFoundError("authorization with id %d not found", *req.Id)
	} else if rows > 1 {
		return berrors.InternalServerError("multiple rows updated for authorization id %d", *req.Id)
	}
	return nil
}

// RevokeCertificate stores revocation information about a certificate. It will only store this
// information if the certificate is not already marked as revoked.
func (ssa *SQLStorageAuthority) RevokeCertificate(ctx context.Context, req *sapb.RevokeCertificateRequest) error {
	revokedDate := time.Unix(0, *req.Date)
	res, err := ssa.dbMap.Exec(
		`UPDATE certificateStatus SET
				status = ?,
				revokedReason = ?,
				revokedDate = ?,
				ocspLastUpdated = ?,
				ocspResponse = ?
			WHERE serial = ? AND status != ?`,
		string(core.OCSPStatusRevoked),
		revocation.Reason(*req.Reason),
		revokedDate,
		revokedDate,
		req.Response,
		*req.Serial,
		string(core.OCSPStatusRevoked),
	)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		// InternalServerError because we expected this certificate status to exist and
		// not be revoked.
		return berrors.InternalServerError("no certificate with serial %s and status %s", *req.Serial, string(core.OCSPStatusRevoked))
	}
	return nil
}

// GetPendingAuthorization2 returns the most recent Pending authorization with
// the given identifier, if available. This method is intended to deprecate
// GetPendingAuthorization. This method only supports DNS identifier types.
func (ssa *SQLStorageAuthority) GetPendingAuthorization2(ctx context.Context, req *sapb.GetPendingAuthorizationRequest) (*corepb.Authorization, error) {
	var am authzModel
	err := ssa.dbMap.WithContext(ctx).SelectOne(
		&am,
		fmt.Sprintf(`SELECT %s FROM authz2 WHERE
			registrationID = :regID AND
			status = :status AND
			expires > :validUntil AND
			identifierType = :dnsType AND
			identifierValue = :ident
			ORDER BY expires ASC
			LIMIT 1 `, authzFields),
		map[string]interface{}{
			"regID":      *req.RegistrationID,
			"status":     statusUint(core.StatusPending),
			"validUntil": time.Unix(0, *req.ValidUntil),
			"dnsType":    identifierTypeToUint[string(identifier.DNS)],
			"ident":      *req.IdentifierValue,
		},
	)
	if err != nil {
		if db.IsNoRows(err) {
			return nil, berrors.NotFoundError("pending authz not found")
		}
		return nil, err
	}
	return modelToAuthzPB(am)
}

// CountPendingAuthorizations2 returns the number of pending, unexpired authorizations
// for the given registration. This method is intended to deprecate CountPendingAuthorizations.
func (ssa *SQLStorageAuthority) CountPendingAuthorizations2(ctx context.Context, req *sapb.RegistrationID) (*sapb.Count, error) {
	var count int64
	err := ssa.dbMap.WithContext(ctx).SelectOne(&count,
		`SELECT COUNT(1) FROM authz2 WHERE
		registrationID = :regID AND
		expires > :expires AND
		status = :status`,
		map[string]interface{}{
			"regID":   *req.Id,
			"expires": ssa.clk.Now(),
			"status":  statusUint(core.StatusPending),
		},
	)
	if err != nil {
		return nil, err
	}
	return &sapb.Count{Count: &count}, nil
}

// GetValidOrderAuthorizations2 is used to find the valid, unexpired authorizations
// associated with a specific order and account ID. This method is intended to
// deprecate GetValidOrderAuthorizations.
func (ssa *SQLStorageAuthority) GetValidOrderAuthorizations2(ctx context.Context, req *sapb.GetValidOrderAuthorizationsRequest) (*sapb.Authorizations, error) {
	var ams []authzModel
	_, err := ssa.dbMap.WithContext(ctx).Select(
		&ams,
		fmt.Sprintf(`SELECT %s FROM authz2
			LEFT JOIN orderToAuthz2 ON authz2.ID = orderToAuthz2.authzID
			WHERE authz2.registrationID = :regID AND
			authz2.expires > :expires AND
			authz2.status = :status AND
			orderToAuthz2.orderID = :orderID`,
			authzFields,
		),
		map[string]interface{}{
			"regID":   *req.AcctID,
			"expires": ssa.clk.Now(),
			"status":  statusUint(core.StatusValid),
			"orderID": *req.Id,
		},
	)
	if err != nil {
		return nil, err
	}

	byName := make(map[string]authzModel)
	for _, am := range ams {
		if uintToIdentifierType[am.IdentifierType] != string(identifier.DNS) {
			return nil, fmt.Errorf("unknown identifier type: %q on authz id %d", am.IdentifierType, am.ID)
		}
		existing, present := byName[am.IdentifierValue]
		if !present || am.Expires.After(existing.Expires) {
			byName[am.IdentifierValue] = am
		}
	}

	return authzModelMapToPB(byName)
}

// CountInvalidAuthorizations2 counts invalid authorizations for a user expiring
// in a given time range. This method is intended to deprecate CountInvalidAuthorizations.
// This method only supports DNS identifier types.
func (ssa *SQLStorageAuthority) CountInvalidAuthorizations2(ctx context.Context, req *sapb.CountInvalidAuthorizationsRequest) (*sapb.Count, error) {
	var count int64
	err := ssa.dbMap.WithContext(ctx).SelectOne(
		&count,
		`SELECT COUNT(1) FROM authz2 WHERE
		registrationID = :regID AND
		status = :status AND
		expires > :expiresEarliest AND
		expires <= :expiresLatest AND
		identifierType = :dnsType AND
		identifierValue = :ident`,
		map[string]interface{}{
			"regID":           *req.RegistrationID,
			"dnsType":         identifierTypeToUint[string(identifier.DNS)],
			"ident":           *req.Hostname,
			"expiresEarliest": time.Unix(0, *req.Range.Earliest),
			"expiresLatest":   time.Unix(0, *req.Range.Latest),
			"status":          statusUint(core.StatusInvalid),
		},
	)
	if err != nil {
		return nil, err
	}
	return &sapb.Count{Count: &count}, nil
}

// GetValidAuthorizations2 returns the latest authorization for all
// domain names that the account has authorizations for. This method is
// intended to deprecate GetValidAuthorizations. This method only supports
// DNS identifier types.
func (ssa *SQLStorageAuthority) GetValidAuthorizations2(ctx context.Context, req *sapb.GetValidAuthorizationsRequest) (*sapb.Authorizations, error) {
	var authzModels []authzModel
	params := []interface{}{
		*req.RegistrationID,
		statusUint(core.StatusValid),
		time.Unix(0, *req.Now),
		identifierTypeToUint[string(identifier.DNS)],
	}
	qmarks := make([]string, len(req.Domains))
	for i, n := range req.Domains {
		qmarks[i] = "?"
		params = append(params, n)
	}
	_, err := ssa.dbMap.Select(
		&authzModels,
		fmt.Sprintf(
			`SELECT %s FROM authz2 WHERE
			registrationID = ? AND
			status = ? AND
			expires > ? AND
			identifierType = ? AND
			identifierValue IN (%s)`,
			authzFields,
			strings.Join(qmarks, ","),
		),
		params...,
	)
	if err != nil {
		return nil, err
	}

	authzMap := make(map[string]authzModel, len(authzModels))
	for _, am := range authzModels {
		// Only allow DNS identifiers
		if uintToIdentifierType[am.IdentifierType] != string(identifier.DNS) {
			continue
		}
		// If there is an existing authorization in the map only replace it with one
		// which has a later expiry.
		if existing, present := authzMap[am.IdentifierValue]; present && am.Expires.Before(existing.Expires) {
			continue
		}
		authzMap[am.IdentifierValue] = am
	}
	return authzModelMapToPB(authzMap)
}

func addKeyHash(db db.Inserter, cert *x509.Certificate) error {
	if cert.RawSubjectPublicKeyInfo == nil {
		return errors.New("certificate has a nil RawSubjectPublicKeyInfo")
	}
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	khm := &keyHashModel{
		KeyHash:      h[:],
		CertNotAfter: cert.NotAfter,
		CertSerial:   core.SerialToString(cert.SerialNumber),
	}
	return db.Insert(khm)
}

var blockedKeysColumns = "keyHash, added, source, comment"

// AddBlockedKey adds a key hash to the blockedKeys table
func (ssa *SQLStorageAuthority) AddBlockedKey(ctx context.Context, req *sapb.AddBlockedKeyRequest) (*corepb.Empty, error) {
	if req == nil || req.KeyHash == nil || req.Added == nil || req.Source == nil {
		return nil, errIncompleteRequest
	}
	sourceInt, ok := stringToSourceInt[*req.Source]
	if !ok {
		return nil, errors.New("unknown source")
	}
	cols, qs := blockedKeysColumns, "?, ?, ?, ?"
	vals := []interface{}{
		req.KeyHash,
		time.Unix(0, *req.Added),
		sourceInt,
		req.Comment,
	}
	if features.Enabled(features.StoreRevokerInfo) && req.RevokedBy != nil {
		cols += ", revokedBy"
		qs += ", ?"
		vals = append(vals, *req.RevokedBy)
	}
	_, err := ssa.dbMap.Exec(
		fmt.Sprintf("INSERT INTO blockedKeys (%s) VALUES (%s)", cols, qs),
		vals...,
	)
	if err != nil {
		if db.IsDuplicate(err) {
			// Ignore duplicate inserts so multiple certs with the same key can
			// be revoked.
			return &corepb.Empty{}, nil
		}
		return nil, err
	}
	return &corepb.Empty{}, nil
}

// KeyBlocked checks if a key, indicated by a hash, is present in the blockedKeys table
func (ssa *SQLStorageAuthority) KeyBlocked(ctx context.Context, req *sapb.KeyBlockedRequest) (*sapb.Exists, error) {
	if req == nil || req.KeyHash == nil {
		return nil, errIncompleteRequest
	}
	exists := false
	var id int64
	if err := ssa.dbMap.SelectOne(&id, `SELECT ID FROM blockedKeys WHERE keyHash = ?`, req.KeyHash); err != nil {
		if db.IsNoRows(err) {
			return &sapb.Exists{Exists: &exists}, nil
		}
		return nil, err
	}
	exists = true
	return &sapb.Exists{Exists: &exists}, nil
}
