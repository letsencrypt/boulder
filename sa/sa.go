package sa

import (
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jmhodges/clock"
	"golang.org/x/net/context"
	"gopkg.in/go-gorp/gorp.v2"
	jose "gopkg.in/square/go-jose.v2"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/revocation"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

type certCountFunc func(db dbSelector, domain string, earliest, latest time.Time) (int, error)
type getChallengesFunc func(db dbSelector, authID string) ([]core.Challenge, error)

// SQLStorageAuthority defines a Storage Authority
type SQLStorageAuthority struct {
	dbMap *gorp.DbMap
	clk   clock.Clock
	log   blog.Logger
	scope metrics.Scope

	// For RPCs that generate multiple, parallelizable SQL queries, this is the
	// max parallelism they will use (to avoid consuming too many MariaDB
	// threads).
	parallelismPerRPC int

	// We use function types here so we can mock out this internal function in
	// unittests.
	countCertificatesByName certCountFunc
	getChallenges           getChallengesFunc
}

func digest256(data []byte) []byte {
	d := sha256.New()
	_, _ = d.Write(data) // Never returns an error
	return d.Sum(nil)
}

// Utility models
type pendingauthzModel struct {
	core.Authorization

	LockCol int64
}

type authzModel struct {
	core.Authorization
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

const (
	authorizationTable        = "authz"
	pendingAuthorizationTable = "pendingAuthorizations"
)

var authorizationTables = []string{
	authorizationTable,
	pendingAuthorizationTable,
}

// NewSQLStorageAuthority provides persistence using a SQL backend for
// Boulder. It will modify the given gorp.DbMap by adding relevant tables.
func NewSQLStorageAuthority(
	dbMap *gorp.DbMap,
	clk clock.Clock,
	logger blog.Logger,
	scope metrics.Scope,
	parallelismPerRPC int,
) (*SQLStorageAuthority, error) {
	SetSQLDebug(dbMap, logger)

	ssa := &SQLStorageAuthority{
		dbMap:             dbMap,
		clk:               clk,
		log:               logger,
		scope:             scope,
		parallelismPerRPC: parallelismPerRPC,
	}

	ssa.countCertificatesByName = ssa.countCertificatesByNameImpl
	ssa.getChallenges = ssa.getChallengesImpl

	return ssa, nil
}

func statusIsPending(status core.AcmeStatus) bool {
	return status == core.StatusPending || status == core.StatusProcessing || status == core.StatusUnknown
}

func existingPending(db dbOneSelector, id string) bool {
	var count int64
	_ = db.SelectOne(&count, "SELECT count(*) FROM pendingAuthorizations WHERE id = :id", map[string]interface{}{"id": id})
	return count > 0
}

func existingFinal(db dbOneSelector, id string) bool {
	var count int64
	_ = db.SelectOne(&count, "SELECT count(*) FROM authz WHERE id = :id", map[string]interface{}{"id": id})
	return count > 0
}

func existingRegistration(tx *gorp.Transaction, id int64) bool {
	var count int64
	_ = tx.SelectOne(&count, "SELECT count(*) FROM registrations WHERE id = :id", map[string]interface{}{"id": id})
	return count > 0
}

func updateChallenges(db dbSelectExecer, authID string, challenges []core.Challenge) error {
	var challs []challModel
	_, err := db.Select(
		&challs,
		getChallengesQuery,
		map[string]interface{}{"authID": authID},
	)
	if err != nil {
		return err
	}
	if len(challs) != len(challenges) {
		return fmt.Errorf("Invalid number of challenges provided")
	}
	for i, authChall := range challenges {
		if challs[i].AuthorizationID != authID {
			return fmt.Errorf("challenge authorization ID %q didn't match associated authorization ID %q", challs[i].AuthorizationID, authID)
		}
		chall, err := challengeToModel(&authChall, authID)
		if err != nil {
			return err
		}
		chall.ID = challs[i].ID
		_, err = db.Exec(
			`UPDATE challenges SET
				status = ?,
				error = ?,
				validationRecord = ?
			WHERE status = ? AND id = ?`,
			string(chall.Status),
			chall.Error,
			chall.ValidationRecord,
			string(core.StatusPending),
			chall.ID)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetRegistration obtains a Registration by ID
func (ssa *SQLStorageAuthority) GetRegistration(ctx context.Context, id int64) (core.Registration, error) {
	const query = "WHERE id = ?"
	model, err := selectRegistration(ssa.dbMap.WithContext(ctx), query, id)
	if err == sql.ErrNoRows {
		return core.Registration{}, berrors.NotFoundError("registration with ID '%d' not found", id)
	}
	if err != nil {
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
	sha, err := core.KeyDigest(key.Key)
	if err != nil {
		return core.Registration{}, err
	}
	model, err := selectRegistration(ssa.dbMap.WithContext(ctx), query, sha)
	if err == sql.ErrNoRows {
		return core.Registration{}, berrors.NotFoundError("no registrations with public key sha256 %q", sha)
	}
	if err != nil {
		return core.Registration{}, err
	}

	return modelToRegistration(model)
}

// GetAuthorization obtains an Authorization by ID
func (ssa *SQLStorageAuthority) GetAuthorization(ctx context.Context, id string) (core.Authorization, error) {
	authz := core.Authorization{}
	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return authz, err
	}
	txWithCtx := tx.WithContext(ctx)

	pa, err := selectPendingAuthz(txWithCtx, "WHERE id = ?", id)
	if err != nil && err != sql.ErrNoRows {
		return authz, Rollback(tx, err)
	}
	if err == sql.ErrNoRows {
		var fa authzModel
		err := txWithCtx.SelectOne(&fa, fmt.Sprintf("SELECT %s FROM authz WHERE id = ?", authzFields), id)
		if err != nil && err != sql.ErrNoRows {
			return authz, Rollback(tx, err)
		} else if err == sql.ErrNoRows {
			// If there was no result in either the pending authz table or the authz
			// table then return a `berrors.NotFound` instance (or a rollback error if
			// the transaction rollback fails)
			return authz, Rollback(
				tx,
				berrors.NotFoundError("no authorization found with id %q", id))
		}
		authz = fa.Authorization
	} else {
		authz = pa.Authorization
	}

	authz.Challenges, err = ssa.getChallenges(txWithCtx, authz.ID)
	if err != nil {
		return authz, Rollback(tx, err)
	}

	return authz, tx.Commit()
}

// GetValidAuthorizations returns the latest authorization object for all
// domain names from the parameters that the account has authorizations for.
func (ssa *SQLStorageAuthority) GetValidAuthorizations(
	ctx context.Context,
	registrationID int64,
	names []string,
	now time.Time) (map[string]*core.Authorization, error) {
	return ssa.getAuthorizations(
		ctx,
		authorizationTable,
		string(core.StatusValid),
		registrationID,
		names,
		now,
		false)
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

func (ssa *SQLStorageAuthority) CountCertificatesByExactNames(ctx context.Context, domains []string, earliest, latest time.Time) ([]*sapb.CountByNames_MapElement, error) {
	var ret []*sapb.CountByNames_MapElement
	for _, domain := range domains {
		currentCount, err := ssa.countCertificatesByExactName(
			ssa.dbMap.WithContext(ctx), domain, earliest, latest)
		if err != nil {
			return ret, err
		}
		name := string(domain)
		pbCount := int64(currentCount)
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

const countCertificatesSelect = `
		 SELECT serial from issuedNames
		 WHERE (reversedName = :reversedDomain OR
			      reversedName LIKE CONCAT(:reversedDomain, ".%"))
		 AND notBefore > :earliest AND notBefore <= :latest;`

const countCertificatesExactSelect = `
		 SELECT serial from issuedNames
		 WHERE reversedName = :reversedDomain
		 AND notBefore > :earliest AND notBefore <= :latest;`

// countCertificatesByNames returns, for a single domain, the count of
// certificates issued in the given time range for that domain and its
// subdomains.
func (ssa *SQLStorageAuthority) countCertificatesByNameImpl(
	db dbSelector,
	domain string,
	earliest,
	latest time.Time,
) (int, error) {
	return ssa.countCertificates(db, domain, earliest, latest, countCertificatesSelect)
}

// countCertificatesByExactNames returns, for a single domain, the count of
// certificates issued in the given time range for that domain. In contrast to
// countCertificatesByNames subdomains are NOT considered.
func (ssa *SQLStorageAuthority) countCertificatesByExactName(
	db dbSelector,
	domain string,
	earliest,
	latest time.Time,
) (int, error) {
	return ssa.countCertificates(db, domain, earliest, latest, countCertificatesExactSelect)
}

// countCertificates returns, for a single domain, the count of
// non-renewal certificate issuances in the given time range for that domain using the
// provided query, assumed to be either `countCertificatesExactSelect` or
// `countCertificatesSelect`. If the `AllowRenewalFirstRL` feature flag is set,
// renewals of certificates issued within the same window are considered "free"
// and are not counted.
func (ssa *SQLStorageAuthority) countCertificates(db dbSelector, domain string, earliest, latest time.Time, query string) (int, error) {
	var serials []string
	_, err := db.Select(
		&serials,
		query,
		map[string]interface{}{
			"reversedDomain": ReverseName(domain),
			"earliest":       earliest,
			"latest":         latest,
		})
	if err == sql.ErrNoRows {
		return 0, nil
	} else if err != nil {
		return 0, err
	}

	// If the `AllowRenewalFirstRL` feature flag is enabled then do the work
	// required to discount renewals
	if features.Enabled(features.AllowRenewalFirstRL) {
		// If there are no serials found, short circuit since there isn't subsequent
		// work to do
		if len(serials) == 0 {
			return 0, nil
		}

		// Find all FQDN Set Hashes with the serials from the issuedNames table that
		// were visible within our search window
		fqdnSets, err := ssa.getFQDNSetsBySerials(db, serials)
		if err != nil {
			return 0, err
		}

		// Using those FQDN Set Hashes, we can then find all of the non-renewal
		// issuances with a second query against the fqdnSets table using the set
		// hashes we know about
		nonRenewalIssuances, err := ssa.getNewIssuancesByFQDNSet(db, fqdnSets, earliest)
		if err != nil {
			return 0, err
		}
		return nonRenewalIssuances, nil
	} else {
		// Otherwise, use the preexisting behaviour and deduplicate by serials
		// returning a count of unique serials qignoring any potential renewals
		serialMap := make(map[string]struct{}, len(serials))
		for _, s := range serials {
			serialMap[s] = struct{}{}
		}
		return len(serialMap), nil
	}
}

// GetCertificate takes a serial number and returns the corresponding
// certificate, or error if it does not exist.
func (ssa *SQLStorageAuthority) GetCertificate(ctx context.Context, serial string) (core.Certificate, error) {
	if !core.ValidSerial(serial) {
		err := fmt.Errorf("Invalid certificate serial %s", serial)
		return core.Certificate{}, err
	}

	cert, err := SelectCertificate(ssa.dbMap.WithContext(ctx), "WHERE serial = ?", serial)
	if err == sql.ErrNoRows {
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

	var status core.CertificateStatus
	statusObj, err := ssa.dbMap.WithContext(ctx).Get(certStatusModel{}, serial)
	if err != nil {
		return status, err
	}
	if statusObj == nil {
		return status, nil
	}
	statusModel := statusObj.(*certStatusModel)
	status = core.CertificateStatus{
		Serial:                statusModel.Serial,
		Status:                statusModel.Status,
		OCSPLastUpdated:       statusModel.OCSPLastUpdated,
		RevokedDate:           statusModel.RevokedDate,
		RevokedReason:         statusModel.RevokedReason,
		LastExpirationNagSent: statusModel.LastExpirationNagSent,
		OCSPResponse:          statusModel.OCSPResponse,
		NotAfter:              statusModel.NotAfter,
		IsExpired:             statusModel.IsExpired,
	}

	return status, nil
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
		return reg, err
	}
	return modelToRegistration(rm)
}

// MarkCertificateRevoked stores the fact that a certificate is revoked, along
// with a timestamp and a reason.
func (ssa *SQLStorageAuthority) MarkCertificateRevoked(ctx context.Context, serial string, reasonCode revocation.Reason) error {
	var err error
	if _, err = ssa.GetCertificate(ctx, serial); err != nil {
		return fmt.Errorf(
			"Unable to mark certificate %s revoked: cert not found.", serial)
	}

	if _, err = ssa.GetCertificateStatus(ctx, serial); err != nil {
		return fmt.Errorf(
			"Unable to mark certificate %s revoked: cert status not found.", serial)
	}

	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return err
	}
	txWithCtx := tx.WithContext(ctx)

	const statusQuery = "WHERE serial = ?"
	statusObj, err := SelectCertificateStatus(txWithCtx, statusQuery, serial)
	if err == sql.ErrNoRows {
		err = fmt.Errorf("No certificate with serial %s", serial)
		err = Rollback(tx, err)
		return err
	}
	if err != nil {
		err = Rollback(tx, err)
		return err
	}

	var n int64
	now := ssa.clk.Now()
	statusObj.Status = core.OCSPStatusRevoked
	statusObj.RevokedDate = now
	statusObj.RevokedReason = reasonCode
	n, err = tx.Update(&statusObj)
	if err != nil {
		err = Rollback(tx, err)
		return err
	}
	if n == 0 {
		err = berrors.InternalServerError("no certificate updated")
		err = Rollback(tx, err)
		return err
	}

	return tx.Commit()
}

// UpdateRegistration stores an updated Registration
func (ssa *SQLStorageAuthority) UpdateRegistration(ctx context.Context, reg core.Registration) error {
	const query = "WHERE id = ?"
	model, err := selectRegistration(ssa.dbMap.WithContext(ctx), query, reg.ID)
	if err == sql.ErrNoRows {
		return berrors.NotFoundError("registration with ID '%d' not found", reg.ID)
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
		return err
	}
	if n == 0 {
		return berrors.NotFoundError("registration with ID '%d' not found", reg.ID)
	}

	return nil
}

// NewPendingAuthorization retrieves a pending authorization for
// authz.Identifier if one exists, or creates a new one otherwise.
func (ssa *SQLStorageAuthority) NewPendingAuthorization(ctx context.Context, authz core.Authorization) (core.Authorization, error) {
	var output core.Authorization

	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return output, err
	}
	txWithCtx := tx.WithContext(ctx)

	// Create a random ID and check that it doesn't exist already
	authz.ID = core.NewToken()
	for existingPending(txWithCtx, authz.ID) ||
		existingFinal(txWithCtx, authz.ID) {
		authz.ID = core.NewToken()
	}

	// Insert a stub row in pending
	pendingAuthz := pendingauthzModel{Authorization: authz}
	err = txWithCtx.Insert(&pendingAuthz)
	if err != nil {
		err = Rollback(tx, err)
		return output, err
	}

	for i, c := range authz.Challenges {
		challModel, err := challengeToModel(&c, pendingAuthz.ID)
		if err != nil {
			err = Rollback(tx, err)
			return output, err
		}
		// Magic happens here: Gorp will modify challModel, setting challModel.ID
		// to the auto-increment primary key. This is important because we want
		// the challenge objects inside the Authorization we return to know their
		// IDs, so they can have proper URLs.
		// See https://godoc.org/github.com/coopernurse/gorp#DbMap.Insert
		err = txWithCtx.Insert(challModel)
		if err != nil {
			err = Rollback(tx, err)
			return output, err
		}
		challenge, err := modelToChallenge(challModel)
		if err != nil {
			err = Rollback(tx, err)
			return output, err
		}
		authz.Challenges[i] = challenge
	}

	err = tx.Commit()
	output = pendingAuthz.Authorization
	output.Challenges = authz.Challenges
	return output, err
}

// GetPendingAuthorization returns the most recent Pending authorization
// with the given identifier, if available.
func (ssa *SQLStorageAuthority) GetPendingAuthorization(
	ctx context.Context,
	req *sapb.GetPendingAuthorizationRequest,
) (*core.Authorization, error) {
	identifierJSON, err := json.Marshal(core.AcmeIdentifier{
		Type:  core.IdentifierType(*req.IdentifierType),
		Value: *req.IdentifierValue,
	})
	if err != nil {
		return nil, err
	}

	// Note: This will use the index on `registrationId`, `expires`, which should
	// keep the amount of scanning to a minimum. That index does not include the
	// identifier, so accounts with huge numbers of pending authzs may result in
	// slow queries here.
	pa, err := selectPendingAuthz(ssa.dbMap.WithContext(ctx),
		`WHERE registrationID = :regID
			 AND identifier = :identifierJSON
			 AND status = :status
			 AND expires > :validUntil
		 ORDER BY expires ASC
		 LIMIT 1`,
		map[string]interface{}{
			"regID":          *req.RegistrationID,
			"identifierJSON": identifierJSON,
			"status":         string(core.StatusPending),
			"validUntil":     time.Unix(0, *req.ValidUntil),
		})
	if err == sql.ErrNoRows {
		return nil, berrors.NotFoundError("pending authz not found")
	} else if err == nil {
		// We found an authz, but we still need to fetch its challenges. To
		// simplify things, just call GetAuthorization, which takes care of that.
		ssa.scope.Inc("reused_authz", 1)
		authz, err := ssa.GetAuthorization(ctx, pa.ID)
		return &authz, err
	} else {
		// Any error other than ErrNoRows; return the error
		return nil, err
	}

}

// UpdatePendingAuthorization updates a Pending Authorization's Challenges.
// Despite what the name "UpdatePendingAuthorization" (preserved for legacy
// reasons) may indicate, the pending authorization table row is not changed,
// only the associated challenges by way of `sa.updateChallenges`.
func (ssa *SQLStorageAuthority) UpdatePendingAuthorization(ctx context.Context, authz core.Authorization) error {
	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return err
	}
	txWithCtx := tx.WithContext(ctx)

	if !statusIsPending(authz.Status) {
		err = berrors.WrongAuthorizationStateError("authorization is not pending")
		return Rollback(tx, err)
	}

	if existingFinal(txWithCtx, authz.ID) {
		err = berrors.WrongAuthorizationStateError("cannot update a finalized authorization")
		return Rollback(tx, err)
	}

	if !existingPending(txWithCtx, authz.ID) {
		err = berrors.InternalServerError("authorization with ID '%s' not found", authz.ID)
		return Rollback(tx, err)
	}

	_, err = selectPendingAuthz(txWithCtx, "WHERE id = ?", authz.ID)
	if err == sql.ErrNoRows {
		err = berrors.InternalServerError("authorization with ID '%s' not found", authz.ID)
		return Rollback(tx, err)
	}
	if err != nil {
		return Rollback(tx, err)
	}

	err = updateChallenges(txWithCtx, authz.ID, authz.Challenges)
	if err != nil {
		return Rollback(tx, err)
	}

	return tx.Commit()
}

// FinalizeAuthorization converts a Pending Authorization to a final one. If the
// Authorization is not found a berrors.NotFound result is returned. If the
// Authorization is status pending a berrors.InternalServer error is returned.
func (ssa *SQLStorageAuthority) FinalizeAuthorization(ctx context.Context, authz core.Authorization) error {
	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return err
	}
	txWithCtx := tx.WithContext(ctx)

	// Check that a pending authz exists
	if !existingPending(txWithCtx, authz.ID) {
		err = berrors.NotFoundError("authorization with ID %q not found", authz.ID)
		return Rollback(tx, err)
	}
	if statusIsPending(authz.Status) {
		err = berrors.InternalServerError("authorization to finalize is pending (ID %q)", authz.ID)
		return Rollback(tx, err)
	}

	auth := &authzModel{authz}
	pa, err := selectPendingAuthz(txWithCtx, "WHERE id = ?", authz.ID)
	if err == sql.ErrNoRows {
		return Rollback(tx, berrors.NotFoundError("authorization with ID %q not found", authz.ID))
	}
	if err != nil {
		return Rollback(tx, err)
	}

	err = txWithCtx.Insert(auth)
	if err != nil {
		return Rollback(tx, err)
	}

	_, err = txWithCtx.Delete(pa)
	if err != nil {
		return Rollback(tx, err)
	}

	err = updateChallenges(txWithCtx, authz.ID, authz.Challenges)
	if err != nil {
		return Rollback(tx, err)
	}

	return tx.Commit()
}

// RevokeAuthorizationsByDomain invalidates all pending or finalized authorizations
// for a specific domain
func (ssa *SQLStorageAuthority) RevokeAuthorizationsByDomain(ctx context.Context, ident core.AcmeIdentifier) (int64, int64, error) {
	identifierJSON, err := json.Marshal(ident)
	if err != nil {
		return 0, 0, err
	}
	identifier := string(identifierJSON)
	results := []int64{0, 0}

	now := ssa.clk.Now()
	for i, table := range authorizationTables {
		for {
			authz, err := getAuthorizationIDsByDomain(ssa.dbMap.WithContext(ctx), table, identifier, now)
			if err != nil {
				return results[0], results[1], err
			}
			numAuthz := len(authz)
			if numAuthz == 0 {
				break
			}

			numRevoked, err := revokeAuthorizations(ssa.dbMap.WithContext(ctx), table, authz)
			if err != nil {
				return results[0], results[1], err
			}
			results[i] += numRevoked
			if numRevoked < int64(numAuthz) {
				return results[0], results[1], fmt.Errorf("Didn't revoke all found authorizations")
			}
		}
	}

	return results[0], results[1], nil
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

	certStatus := &certStatusModel{
		Status:          core.OCSPStatus("good"),
		OCSPLastUpdated: time.Time{},
		OCSPResponse:    []byte{},
		Serial:          serial,
		RevokedDate:     time.Time{},
		RevokedReason:   0,
		NotAfter:        parsedCertificate.NotAfter,
	}
	if len(ocspResponse) != 0 {
		certStatus.OCSPResponse = ocspResponse
		certStatus.OCSPLastUpdated = ssa.clk.Now()
	}

	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return "", err
	}
	txWithCtx := tx.WithContext(ctx)

	// Note: will fail on duplicate serials. Extremely unlikely to happen and soon
	// to be fixed by redesign. Reference issue
	// https://github.com/letsencrypt/boulder/issues/2265 for more
	err = txWithCtx.Insert(cert)
	if err != nil {
		if strings.HasPrefix(err.Error(), "Error 1062: Duplicate entry") {
			err = berrors.DuplicateError("cannot add a duplicate cert")
		}
		return "", Rollback(tx, err)
	}

	err = txWithCtx.Insert(certStatus)
	if err != nil {
		if strings.HasPrefix(err.Error(), "Error 1062: Duplicate entry") {
			err = berrors.DuplicateError("cannot add a duplicate cert status")
		}
		return "", Rollback(tx, err)
	}

	err = addIssuedNames(txWithCtx, parsedCertificate)
	if err != nil {
		return "", Rollback(tx, err)
	}

	err = addFQDNSet(
		txWithCtx,
		parsedCertificate.DNSNames,
		serial,
		parsedCertificate.NotBefore,
		parsedCertificate.NotAfter,
	)
	if err != nil {
		return "", Rollback(tx, err)
	}

	return digest, tx.Commit()
}

// CountPendingAuthorizations returns the number of pending, unexpired
// authorizations for the given registration.
func (ssa *SQLStorageAuthority) CountPendingAuthorizations(ctx context.Context, regID int64) (count int, err error) {
	err = ssa.dbMap.WithContext(ctx).SelectOne(&count,
		`SELECT count(1) FROM pendingAuthorizations
		WHERE registrationID = :regID AND
		expires > :now AND
		status = :pending`,
		map[string]interface{}{
			"regID":   regID,
			"now":     ssa.clk.Now(),
			"pending": string(core.StatusPending),
		})
	return
}

func (ssa *SQLStorageAuthority) CountOrders(ctx context.Context, acctID int64, earliest, latest time.Time) (int, error) {
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

// CountInvalidAuthorizations counts invalid authorizations for a user expiring
// in a given time range.
// authorizations for the give registration.
func (ssa *SQLStorageAuthority) CountInvalidAuthorizations(
	ctx context.Context,
	req *sapb.CountInvalidAuthorizationsRequest,
) (count *sapb.Count, err error) {
	identifier := core.AcmeIdentifier{
		Type:  core.IdentifierDNS,
		Value: *req.Hostname,
	}

	idJSON, err := json.Marshal(identifier)
	if err != nil {
		return nil, err
	}

	count = &sapb.Count{
		Count: new(int64),
	}
	err = ssa.dbMap.WithContext(ctx).SelectOne(count.Count,
		`SELECT COUNT(1) FROM authz
		WHERE registrationID = :regID AND
		identifier = :identifier AND
		expires > :earliest AND
		expires <= :latest AND
		status = :invalid`,
		map[string]interface{}{
			"regID":      *req.RegistrationID,
			"identifier": idJSON,
			"earliest":   time.Unix(0, *req.Range.Earliest),
			"latest":     time.Unix(0, *req.Range.Latest),
			"invalid":    string(core.StatusInvalid),
		})
	return
}

func hashNames(names []string) []byte {
	names = core.UniqueLowerNames(names)
	hash := sha256.Sum256([]byte(strings.Join(names, ",")))
	return hash[:]
}

func addFQDNSet(db dbInserter, names []string, serial string, issued time.Time, expires time.Time) error {
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
	db dbInserter,
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
	db dbExecer,
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

func addIssuedNames(db dbExecer, cert *x509.Certificate) error {
	var qmarks []string
	var values []interface{}
	for _, name := range cert.DNSNames {
		values = append(values,
			ReverseName(name),
			core.SerialToString(cert.SerialNumber),
			cert.NotBefore)
		qmarks = append(qmarks, "(?, ?, ?)")
	}
	query := `INSERT INTO issuedNames (reversedName, serial, notBefore) VALUES ` + strings.Join(qmarks, ", ") + `;`
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
	db dbSelector,
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
	_, err := db.Select(
		&fqdnSets,
		query,
		params...)

	if err != nil {
		return nil, err
	}

	// The serials existed when we found them in issuedNames, they should continue
	// to exist here. Otherwise an internal consistency violation occured and
	// needs to be audit logged
	if err == sql.ErrNoRows {
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
	db dbSelector,
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
	_, err := db.Select(
		&results,
		query,
		params...)
	if err != nil && err != sql.ErrNoRows {
		return -1, err
	}

	// If there are no results we have encountered a major error and
	// should loudly complain
	if err == sql.ErrNoRows || len(results) == 0 {
		ssa.log.AuditErrf("Found no results from fqdnSets for setHashes known to exist: %#v", fqdnSets)
		return 0, err
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
	var count int64
	err := ssa.dbMap.WithContext(ctx).SelectOne(
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
// was issued by the provided registration ID. Note: This means that if two
// different accounts were issuing certificates for a domain, only one gets the
// right to revalidate using TLS-SNI-01. We think this is an acceptable tradeoff
// of complexity versus coverage, though we may reconsider in the future.
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
	if err == sql.ErrNoRows {
		return notExists, nil
	}
	if err != nil {
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
	// If no rows found, that means the certificate we found in issuedNames wasn't
	// issued by the registration ID we are checking right now, but is not an
	// error.
	if err == sql.ErrNoRows {
		return notExists, nil
	}
	if err != nil {
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

// DeactivateAuthorization deactivates a currently valid or pending authorization
func (ssa *SQLStorageAuthority) DeactivateAuthorization(ctx context.Context, id string) error {
	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return err
	}
	txWithCtx := tx.WithContext(ctx)

	if existingPending(txWithCtx, id) {
		authzObj, err := txWithCtx.Get(&pendingauthzModel{}, id)
		if err != nil {
			return Rollback(tx, err)
		}
		if authzObj == nil {
			// InternalServerError because existingPending already told us it existed
			return Rollback(tx, berrors.InternalServerError("failure retrieving pending authorization"))
		}
		authz := authzObj.(*pendingauthzModel)
		if authz.Status != core.StatusPending {
			return Rollback(tx, berrors.WrongAuthorizationStateError("authorization not pending"))
		}
		result, err := txWithCtx.Delete(authzObj)
		if err != nil {
			return Rollback(tx, err)
		}
		if result != 1 {
			return Rollback(tx, berrors.InternalServerError("wrong number of rows deleted: expected 1, got %d", result))
		}
		authz.Status = core.StatusDeactivated
		err = txWithCtx.Insert(&authzModel{authz.Authorization})
		if err != nil {
			return Rollback(tx, err)
		}
	} else {
		_, err = txWithCtx.Exec(
			`UPDATE authz SET status = ? WHERE id = ? and status = ?`,
			string(core.StatusDeactivated),
			id,
			string(core.StatusValid),
		)
		if err != nil {
			return Rollback(tx, err)
		}
	}

	return tx.Commit()
}

// NewOrder adds a new v2 style order to the database
func (ssa *SQLStorageAuthority) NewOrder(ctx context.Context, req *corepb.Order) (*corepb.Order, error) {
	order := &orderModel{
		RegistrationID: *req.RegistrationID,
		Expires:        time.Unix(0, *req.Expires),
		Created:        ssa.clk.Now(),
	}

	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return nil, err
	}
	txWithCtx := tx.WithContext(ctx)

	if err := txWithCtx.Insert(order); err != nil {
		return nil, Rollback(tx, err)
	}

	for _, id := range req.Authorizations {
		otoa := &orderToAuthzModel{
			OrderID: order.ID,
			AuthzID: id,
		}
		if err := txWithCtx.Insert(otoa); err != nil {
			return nil, Rollback(tx, err)
		}
	}

	for _, name := range req.Names {
		reqdName := &requestedNameModel{
			OrderID:      order.ID,
			ReversedName: ReverseName(name),
		}
		if err := txWithCtx.Insert(reqdName); err != nil {
			return nil, Rollback(tx, err)
		}
	}

	// Add an FQDNSet entry for the order
	if err := addOrderFQDNSet(
		txWithCtx, req.Names, order.ID, order.RegistrationID, order.Expires); err != nil {
		return nil, Rollback(tx, err)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	// Update the request with the ID that the order received
	req.Id = &order.ID
	// Update the request with the created timestamp from the model
	createdTS := order.Created.UnixNano()
	req.Created = &createdTS
	// A new order is never processing because it can't have been finalized yet
	processingStatus := false
	req.BeganProcessing = &processingStatus

	// Calculate the order status before returning it. Since it may have reused all
	// valid authorizations the order may be "born" in a ready status.
	status, err := ssa.statusForOrder(ctx, req)
	if err != nil {
		return nil, err
	}
	req.Status = &status
	return req, nil
}

// SetOrderProcessing updates a provided *corepb.Order in pending status to be
// in processing status by updating the `beganProcessing` field of the
// corresponding Order table row in the DB.
func (ssa *SQLStorageAuthority) SetOrderProcessing(ctx context.Context, req *corepb.Order) error {
	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return err
	}
	txWithCtx := tx.WithContext(ctx)

	result, err := txWithCtx.Exec(`
		UPDATE orders
		SET beganProcessing = ?
		WHERE id = ?
		AND beganProcessing = ?`,
		true,
		*req.Id,
		false)
	if err != nil {
		err = berrors.InternalServerError("error updating order to beganProcessing status")
		return Rollback(tx, err)
	}

	n, err := result.RowsAffected()
	if err != nil || n == 0 {
		err = berrors.InternalServerError("no order updated to beganProcessing status")
		return Rollback(tx, err)
	}

	return tx.Commit()
}

// SetOrderError updates a provided Order's error field.
func (ssa *SQLStorageAuthority) SetOrderError(ctx context.Context, order *corepb.Order) error {
	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return err
	}
	txWithCtx := tx.WithContext(ctx)

	om, err := orderToModel(order)
	if err != nil {
		return Rollback(tx, err)
	}

	result, err := txWithCtx.Exec(`
		UPDATE orders
		SET error = ?
		WHERE id = ?`,
		om.Error,
		om.ID)
	if err != nil {
		err = berrors.InternalServerError("error updating order error field")
		return Rollback(tx, err)
	}

	n, err := result.RowsAffected()
	if err != nil || n == 0 {
		err = berrors.InternalServerError("no order updated with new error field")
		return Rollback(tx, err)
	}

	return tx.Commit()
}

// FinalizeOrder finalizes a provided *corepb.Order by persisting the
// CertificateSerial and a valid status to the database. No fields other than
// CertificateSerial and the order ID on the provided order are processed (e.g.
// this is not a generic update RPC).
func (ssa *SQLStorageAuthority) FinalizeOrder(ctx context.Context, req *corepb.Order) error {
	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return err
	}
	txWithCtx := tx.WithContext(ctx)

	result, err := txWithCtx.Exec(`
		UPDATE orders
		SET certificateSerial = ?
		WHERE id = ? AND
		beganProcessing = true`,
		*req.CertificateSerial,
		*req.Id)
	if err != nil {
		err = berrors.InternalServerError("error updating order for finalization")
		return Rollback(tx, err)
	}

	n, err := result.RowsAffected()
	if err != nil || n == 0 {
		err = berrors.InternalServerError("no order updated for finalization")
		return Rollback(tx, err)
	}

	// Delete the orderFQDNSet row for the order now that it has been finalized.
	// We use this table for order reuse and should not reuse a finalized order.
	if err := deleteOrderFQDNSet(txWithCtx, *req.Id); err != nil {
		return Rollback(tx, err)
	}

	return tx.Commit()
}

func (ssa *SQLStorageAuthority) authzForOrder(ctx context.Context, orderID int64) ([]string, error) {
	var ids []string
	_, err := ssa.dbMap.WithContext(ctx).Select(
		&ids, "SELECT authzID FROM orderToAuthz WHERE orderID = ?", orderID)
	if err != nil {
		return nil, err
	}
	return ids, nil
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
	if err == sql.ErrNoRows || omObj == nil {
		return nil, berrors.NotFoundError("no order found for ID %d", *req.Id)
	}
	if err != nil {
		return nil, err
	}
	order, err := modelToOrder(omObj.(*orderModel))
	if err != nil {
		return nil, err
	}
	authzIDs, err := ssa.authzForOrder(ctx, *order.Id)
	if err != nil {
		return nil, err
	}
	for _, authzID := range authzIDs {
		order.Authorizations = append(order.Authorizations, authzID)
	}

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
//   * If any of the order's authorizations are deactivated, the order is deactivated.
//   * If any of the order's authorizations are pending, the order is pending.
//   * If all of the order's authorizations are valid, and there is
//     a certificate serial, the order is valid.
//   * If all of the order's authorizations are valid, and we have began
//     processing, but there is no certificate serial, the order is processing.
//   * If all of the order's authorizations are valid, and we haven't begun
//     processing, then the order is status ready.
// An error is returned for any other case.
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
	authzs, err := ssa.getAllOrderAuthorizations(ctx, *order.Id, *order.RegistrationID)
	// If there was an error getting the authorizations, return it immediately
	if err != nil {
		return "", err
	}

	// If getAllOrderAuthorizations returned a different number of authorization
	// objects than the order's slice of authorization IDs something has gone
	// wrong worth raising an internal error about.
	if len(authzs) != len(order.Authorizations) {
		return "", berrors.InternalServerError(
			"getAllOrderAuthorizations returned the wrong number of authorizations "+
				"(%d vs expected %d) for order %d",
			len(authzs), len(order.Authorizations), *order.Id)
	}

	// Keep a count of the authorizations seen
	invalidAuthzs := 0
	expiredAuthzs := 0
	deactivatedAuthzs := 0
	pendingAuthzs := 0
	validAuthzs := 0

	// Loop over each of the order's authorization objects to examine the authz status
	for _, authz := range authzs {
		switch authz.Status {
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
				"Order is in an invalid state. Authz %s has invalid status %q",
				authz.ID, authz.Status)
		}
		if authz.Expires.Before(ssa.clk.Now()) {
			expiredAuthzs++
		}
	}

	// An order is invalid if **any** of its authzs are invalid
	if invalidAuthzs > 0 {
		return string(core.StatusInvalid), nil
	}
	// An order is invalid if **any** of its authzs are expired
	if expiredAuthzs > 0 {
		return string(core.StatusInvalid), nil
	}
	// An order is deactivated if **any** of its authzs are deactivated
	if deactivatedAuthzs > 0 {
		return string(core.StatusDeactivated), nil
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

func (ssa *SQLStorageAuthority) getAllOrderAuthorizations(
	ctx context.Context,
	orderID, acctID int64) (map[string]*core.Authorization, error) {
	var allAuthzs []*core.Authorization

	for _, table := range authorizationTables {
		var authzs []*core.Authorization
		_, err := ssa.dbMap.WithContext(ctx).Select(
			&authzs,
			fmt.Sprintf(`SELECT %s from %s AS authz
		INNER JOIN orderToAuthz
		ON authz.ID = orderToAuthz.authzID
		WHERE authz.registrationID = ? AND
		orderToAuthz.orderID = ?`, authzFields, table),
			acctID,
			orderID)
		if err != nil {
			return nil, err
		}

		allAuthzs = append(allAuthzs, authzs...)
	}

	// Collapse the returned authorizations into a mapping from name to
	// authorization
	byName := make(map[string]*core.Authorization)
	for _, auth := range allAuthzs {
		// We only expect to get back DNS identifiers
		if auth.Identifier.Type != core.IdentifierDNS {
			return nil, fmt.Errorf("unknown identifier type: %q on authz id %q", auth.Identifier.Type, auth.ID)
		}
		// We don't expect there to be multiple authorizations for the same name
		// within the same order
		if _, present := byName[auth.Identifier.Value]; present {
			return nil, berrors.InternalServerError(
				"Found multiple authorizations within one order for identifier %q",
				auth.Identifier.Value)
		}
		byName[auth.Identifier.Value] = auth
	}
	return byName, nil
}

// GetValidOrderAuthorizations is used to find the valid, unexpired authorizations
// associated with a specific order and account ID.
func (ssa *SQLStorageAuthority) GetValidOrderAuthorizations(
	ctx context.Context,
	req *sapb.GetValidOrderAuthorizationsRequest) (map[string]*core.Authorization, error) {
	now := ssa.clk.Now()
	// Select the full authorization data for all *valid, unexpired*
	// authorizations that are owned by the correct account ID and associated with
	// the given order ID
	var auths []*core.Authorization
	_, err := ssa.dbMap.WithContext(ctx).Select(
		&auths,
		fmt.Sprintf(`SELECT %s FROM %s AS authz
	LEFT JOIN orderToAuthz
	ON authz.ID = orderToAuthz.authzID
	WHERE authz.registrationID = ? AND
	authz.expires > ? AND
	authz.status = ? AND
	orderToAuthz.orderID = ?`, authzFields, authorizationTable),
		*req.AcctID,
		now,
		string(core.StatusValid),
		*req.Id)
	if err != nil {
		return nil, err
	}

	// Collapse & dedupe the returned authorizations into a mapping from name to
	// authorization
	byName := make(map[string]*core.Authorization)
	for _, auth := range auths {
		// We only expect to get back DNS identifiers
		if auth.Identifier.Type != core.IdentifierDNS {
			return nil, fmt.Errorf("unknown identifier type: %q on authz id %q", auth.Identifier.Type, auth.ID)
		}
		existing, present := byName[auth.Identifier.Value]
		if !present || auth.Expires.After(*existing.Expires) {
			// Retrieve challenges for the authz
			auth.Challenges, err = ssa.getChallenges(ssa.dbMap.WithContext(ctx), auth.ID)
			if err != nil {
				return nil, err
			}

			byName[auth.Identifier.Value] = auth
		}
	}
	return byName, nil
}

// GetOrderForNames tries to find a **pending** order with the exact set of
// names requested, associated with the given accountID. Only unexpired orders
// with status pending are considered. If no order meeting these requirements is
// found a nil corepb.Order pointer is returned.
func (ssa *SQLStorageAuthority) GetOrderForNames(
	ctx context.Context,
	req *sapb.GetOrderForNamesRequest) (*corepb.Order, error) {

	// Hash the names requested for lookup in the orderFqdnSets table
	fqdnHash := hashNames(req.Names)

	var orderID int64
	err := ssa.dbMap.WithContext(ctx).SelectOne(&orderID, `
	SELECT orderID
	FROM orderFqdnSets
	WHERE setHash = ?
	AND registrationID = ?
	AND expires > ?`,
		fqdnHash, *req.AcctID, ssa.clk.Now())

	// There isn't an unexpired order for the provided AcctID that has the
	// fqdnHash requested.
	if err == sql.ErrNoRows {
		return nil, berrors.NotFoundError("no order matching request found")
	} else if err != nil {
		// An unexpected error occurred
		return nil, err
	}

	// Get the order
	order, err := ssa.GetOrder(ctx, &sapb.OrderRequest{Id: &orderID})
	if err != nil {
		return nil, err
	}
	// Only return a pending order
	if *order.Status != string(core.StatusPending) {
		return nil, berrors.NotFoundError("no order matching request found")
	}
	return order, nil
}

func (ssa *SQLStorageAuthority) getAuthorizations(
	ctx context.Context,
	table string,
	status string,
	registrationID int64,
	names []string,
	now time.Time,
	requireV2Authzs bool) (map[string]*core.Authorization, error) {
	if len(names) == 0 {
		return nil, berrors.InternalServerError("no names received")
	}

	params := make([]interface{}, len(names))
	qmarks := make([]string, len(names))
	for i, name := range names {
		id := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: name}
		idJSON, err := json.Marshal(id)
		if err != nil {
			return nil, err
		}
		params[i] = string(idJSON)
		qmarks[i] = "?"
	}

	// If requested, filter out V1 authorizations by doing a JOIN on the
	// orderToAuthz table, ensuring that all authorization IDs returned correspond
	// to a V2 order.
	queryPrefix := fmt.Sprintf(`SELECT %s FROM %s`, authzFields, table)
	if requireV2Authzs {
		queryPrefix = queryPrefix + `
		JOIN orderToAuthz
			ON ID = authzID`
	}

	var auths []*core.Authorization
	_, err := ssa.dbMap.WithContext(ctx).Select(
		&auths,
		fmt.Sprintf(`%s
		WHERE registrationID = ? AND
		expires > ? AND
		status = ? AND
		identifier IN (%s)`,
			queryPrefix, strings.Join(qmarks, ",")),
		append([]interface{}{registrationID, now, status}, params...)...)
	if err != nil {
		return nil, err
	}

	byName := make(map[string]*core.Authorization)
	for _, auth := range auths {
		// No real life authorizations should have a nil expires. If we find them,
		// don't consider them valid.
		if auth.Expires == nil {
			continue
		}

		if auth.Identifier.Type != core.IdentifierDNS {
			return nil, fmt.Errorf("unknown identifier type: %q on authz id %q", auth.Identifier.Type, auth.ID)
		}
		existing, present := byName[auth.Identifier.Value]
		if !present || auth.Expires.After(*existing.Expires) {
			byName[auth.Identifier.Value] = auth
		}
	}

	for _, auth := range byName {
		// Retrieve challenges for the authz
		if auth.Challenges, err = ssa.getChallenges(ssa.dbMap.WithContext(ctx), auth.ID); err != nil {
			return nil, err
		}
	}

	return byName, nil
}

func (ssa *SQLStorageAuthority) getPendingAuthorizations(
	ctx context.Context,
	registrationID int64,
	names []string,
	now time.Time,
	requireV2Authzs bool) (map[string]*core.Authorization, error) {
	return ssa.getAuthorizations(
		ctx,
		pendingAuthorizationTable,
		string(core.StatusPending),
		registrationID,
		names,
		now,
		requireV2Authzs)
}

func authzMapToPB(m map[string]*core.Authorization) (*sapb.Authorizations, error) {
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

// GetAuthorizations returns a map of valid or pending authorizations for as many names as possible
func (ssa *SQLStorageAuthority) GetAuthorizations(
	ctx context.Context,
	req *sapb.GetAuthorizationsRequest) (*sapb.Authorizations, error) {
	authzMap, err := ssa.getAuthorizations(
		ctx,
		authorizationTable,
		string(core.StatusValid),
		*req.RegistrationID,
		req.Domains,
		time.Unix(0, *req.Now),
		*req.RequireV2Authzs,
	)
	if err != nil {
		return nil, err
	}
	if len(authzMap) == len(req.Domains) {
		return authzMapToPB(authzMap)
	}

	// remove names we already have authz for
	remainingNames := []string{}
	for _, name := range req.Domains {
		if _, present := authzMap[name]; !present {
			remainingNames = append(remainingNames, name)
		}
	}
	pendingAuthz, err := ssa.getPendingAuthorizations(
		ctx,
		*req.RegistrationID,
		remainingNames,
		time.Unix(0, *req.Now),
		*req.RequireV2Authzs)
	if err != nil {
		return nil, err
	}
	// merge pending into valid
	for name, a := range pendingAuthz {
		authzMap[name] = a
	}

	// Wildcard domain issuance requires that the authorizations returned by this
	// RPC also include populated challenges such that the caller can know if the
	// challenges meet the wildcard issuance policy (e.g. only 1 DNS-01
	// challenge).
	// Fetch each of the authorizations' associated challenges
	for _, authz := range authzMap {
		authz.Challenges, err = ssa.getChallenges(ssa.dbMap.WithContext(ctx), authz.ID)
	}
	return authzMapToPB(authzMap)
}

// AddPendingAuthorizations creates a batch of pending authorizations and returns their IDs
func (ssa *SQLStorageAuthority) AddPendingAuthorizations(ctx context.Context, req *sapb.AddPendingAuthorizationsRequest) (*sapb.AuthorizationIDs, error) {
	ids := []string{}
	for _, authPB := range req.Authz {
		authz, err := bgrpc.PBToAuthz(authPB)
		if err != nil {
			return nil, err
		}
		result, err := ssa.NewPendingAuthorization(ctx, authz)
		if err != nil {
			return nil, err
		}
		ids = append(ids, result.ID)
	}
	return &sapb.AuthorizationIDs{Ids: ids}, nil
}

func (ssa *SQLStorageAuthority) getChallengesImpl(db dbSelector, authID string) ([]core.Challenge, error) {
	var challObjs []challModel
	_, err := db.Select(
		&challObjs,
		getChallengesQuery,
		map[string]interface{}{"authID": authID},
	)
	if err != nil {
		return nil, err
	}
	var challs []core.Challenge
	for _, c := range challObjs {
		chall, err := modelToChallenge(&c)
		if err != nil {
			return nil, err
		}
		challs = append(challs, chall)
	}
	return challs, nil
}

// NewAuthorization adds a new authz2 style authorization to the database and returns
// either the ID or an error. It will only process corepb.Authorization objects if the
// V2 field is set.
func (ssa *SQLStorageAuthority) NewAuthorization(authz *corepb.Authorization) (int64, error) {
	am, err := authzPBToModel(authz)
	if err != nil {
		return 0, err
	}
	err = ssa.dbMap.Insert(am)
	if err != nil {
		return 0, err
	}
	return am.ID, nil
}

// GetAuthz2 returns the authz2 style authorization identified by the provided ID or an error.
// If no authorization is found matching the ID a berrors.NotFound type error is returned.
func (ssa *SQLStorageAuthority) GetAuthz2(ctx context.Context, id *sapb.AuthorizationID2) (*corepb.Authorization, error) {
	obj, err := ssa.dbMap.Get(authz2Model{}, id.Id)
	if err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, berrors.NotFoundError("authorization %d not found", id)
	}
	return modelToAuthzPB(obj.(*authz2Model))
}
