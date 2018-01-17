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

type certCountFunc func(domain string, earliest, latest time.Time) (int, error)

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

	// We use a function type here so we can mock out this internal function in
	// unittests.
	countCertificatesByName certCountFunc
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

	return ssa, nil
}

func statusIsPending(status core.AcmeStatus) bool {
	return status == core.StatusPending || status == core.StatusProcessing || status == core.StatusUnknown
}

func existingPending(tx *gorp.Transaction, id string) bool {
	var count int64
	_ = tx.SelectOne(&count, "SELECT count(*) FROM pendingAuthorizations WHERE id = :id", map[string]interface{}{"id": id})
	return count > 0
}

func existingFinal(tx *gorp.Transaction, id string) bool {
	var count int64
	_ = tx.SelectOne(&count, "SELECT count(*) FROM authz WHERE id = :id", map[string]interface{}{"id": id})
	return count > 0
}

func existingRegistration(tx *gorp.Transaction, id int64) bool {
	var count int64
	_ = tx.SelectOne(&count, "SELECT count(*) FROM registrations WHERE id = :id", map[string]interface{}{"id": id})
	return count > 0
}

func updateChallenges(authID string, challenges []core.Challenge, tx *gorp.Transaction) error {
	var challs []challModel
	_, err := tx.Select(
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
		chall, err := challengeToModel(&authChall, challs[i].AuthorizationID)
		if err != nil {
			return err
		}
		chall.ID = challs[i].ID
		_, err = tx.Update(chall)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetRegistration obtains a Registration by ID
func (ssa *SQLStorageAuthority) GetRegistration(ctx context.Context, id int64) (core.Registration, error) {
	const query = "WHERE id = ?"
	model, err := selectRegistration(ssa.dbMap, query, id)
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
	model, err := selectRegistration(ssa.dbMap, query, sha)
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
	pa, err := selectPendingAuthz(tx, "WHERE id = ?", id)
	if err != nil && err != sql.ErrNoRows {
		return authz, Rollback(tx, err)
	}
	if err == sql.ErrNoRows {
		var fa authzModel
		err := tx.SelectOne(&fa, fmt.Sprintf("SELECT %s FROM authz WHERE id = ?", authzFields), id)
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

	authz.Challenges, err = ssa.getChallenges(authz.ID)
	if err != nil {
		return authz, err
	}

	return authz, tx.Commit()
}

// GetValidAuthorizations returns the latest authorization object for all
// domain names from the parameters that the account has authorizations for.
func (ssa *SQLStorageAuthority) GetValidAuthorizations(ctx context.Context, registrationID int64, names []string, now time.Time) (map[string]*core.Authorization, error) {
	return ssa.getAuthorizations(ctx, authorizationTable, string(core.StatusValid), registrationID, names, now)
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
	err := ssa.dbMap.SelectOne(
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
	err := ssa.dbMap.SelectOne(
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
				currentCount, err := ssa.countCertificatesByName(domain, earliest, latest)
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
		currentCount, err := ssa.countCertificatesByExactName(domain, earliest, latest)
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
func (ssa *SQLStorageAuthority) countCertificatesByNameImpl(domain string, earliest, latest time.Time) (int, error) {
	return ssa.countCertificates(domain, earliest, latest, countCertificatesSelect)
}

// countCertificatesByExactNames returns, for a single domain, the count of
// certificates issued in the given time range for that domain. In contrast to
// countCertificatesByNames subdomains are NOT considered.
func (ssa *SQLStorageAuthority) countCertificatesByExactName(domain string, earliest, latest time.Time) (int, error) {
	return ssa.countCertificates(domain, earliest, latest, countCertificatesExactSelect)
}

// countCertificates returns, for a single domain, the count of
// non-renewal certificate issuances in the given time range for that domain using the
// provided query, assumed to be either `countCertificatesExactSelect` or
// `countCertificatesSelect`. If the `AllowRenewalFirstRL` feature flag is set,
// renewals of certificates issued within the same window are considered "free"
// and are not counted.
func (ssa *SQLStorageAuthority) countCertificates(domain string, earliest, latest time.Time, query string) (int, error) {
	var serials []string
	_, err := ssa.dbMap.Select(
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
		fqdnSets, err := ssa.getFQDNSetsBySerials(serials)
		if err != nil {
			return 0, err
		}

		// Using those FQDN Set Hashes, we can then find all of the non-renewal
		// issuances with a second query against the fqdnSets table using the set
		// hashes we know about
		nonRenewalIssuances, err := ssa.getNewIssuancesByFQDNSet(fqdnSets, earliest)
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

	cert, err := SelectCertificate(ssa.dbMap, "WHERE serial = ?", serial)
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
	statusObj, err := ssa.dbMap.Get(certStatusModel{}, serial)
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
	err = ssa.dbMap.Insert(rm)
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

	const statusQuery = "WHERE serial = ?"
	statusObj, err := SelectCertificateStatus(tx, statusQuery, serial)
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
	model, err := selectRegistration(ssa.dbMap, query, reg.ID)
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
	n, err := ssa.dbMap.Update(updatedRegModel)
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

	// Create a random ID and check that it doesn't exist already
	authz.ID = core.NewToken()
	for existingPending(tx, authz.ID) || existingFinal(tx, authz.ID) {
		authz.ID = core.NewToken()
	}

	// Insert a stub row in pending
	pendingAuthz := pendingauthzModel{Authorization: authz}
	err = tx.Insert(&pendingAuthz)
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
		err = tx.Insert(challModel)
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
	pa, err := selectPendingAuthz(ssa.dbMap,
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

	if !statusIsPending(authz.Status) {
		err = berrors.WrongAuthorizationStateError("authorization is not pending")
		return Rollback(tx, err)
	}

	if existingFinal(tx, authz.ID) {
		err = berrors.WrongAuthorizationStateError("cannot update a finalized authorization")
		return Rollback(tx, err)
	}

	if !existingPending(tx, authz.ID) {
		err = berrors.InternalServerError("authorization with ID '%d' not found", authz.ID)
		return Rollback(tx, err)
	}

	_, err = selectPendingAuthz(tx, "WHERE id = ?", authz.ID)
	if err == sql.ErrNoRows {
		err = berrors.InternalServerError("authorization with ID '%d' not found", authz.ID)
		return Rollback(tx, err)
	}
	if err != nil {
		return Rollback(tx, err)
	}

	err = updateChallenges(authz.ID, authz.Challenges, tx)
	if err != nil {
		return Rollback(tx, err)
	}

	return tx.Commit()
}

// FinalizeAuthorization converts a Pending Authorization to a final one. If the
// Authorization is not found a berrors.NotFound result is returned. If the
// Authorization is status pending an berrors.InternalServer error is returned.
func (ssa *SQLStorageAuthority) FinalizeAuthorization(ctx context.Context, authz core.Authorization) error {
	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return err
	}

	// Check that a pending authz exists
	if !existingPending(tx, authz.ID) {
		err = berrors.NotFoundError("authorization with ID %q not found", authz.ID)
		return Rollback(tx, err)
	}
	if statusIsPending(authz.Status) {
		err = berrors.InternalServerError("authorization to finalize is pending (ID %q)", authz.ID)
		return Rollback(tx, err)
	}

	auth := &authzModel{authz}
	pa, err := selectPendingAuthz(tx, "WHERE id = ?", authz.ID)
	if err == sql.ErrNoRows {
		return Rollback(tx, berrors.NotFoundError("authorization with ID %q not found", authz.ID))
	}
	if err != nil {
		return Rollback(tx, err)
	}

	err = tx.Insert(auth)
	if err != nil {
		return Rollback(tx, err)
	}

	_, err = tx.Delete(pa)
	if err != nil {
		return Rollback(tx, err)
	}

	err = updateChallenges(authz.ID, authz.Challenges, tx)
	if err != nil {
		return Rollback(tx, err)
	}

	// When an authorization is being finalized to an invalid state we need to see
	// if there is an order associated with this authorization that itself should
	// now become invalid as a result of the authz being invalid.
	if authz.Status == core.StatusInvalid {
		// Try to find an order associated with this authz ID. There may not be one if
		// this is a legacy V1 authorization from the new-authz endpoint.
		orderID, err := ssa.orderIDForAuthz(tx, authz.ID)
		// If there was an error, and it wasn't a no-result error, then we encountered
		// something unexpected and must rollback
		if err != nil && err != sql.ErrNoRows {
			return Rollback(tx, err)
		}
		// If the err was nil then orderID is an associated order for this authz
		if err == nil {
			// Set the order to invalid
			err := ssa.setOrderInvalid(ctx, tx, &corepb.Order{
				Id: &orderID,
			})
			if err != nil {
				return Rollback(tx, err)
			}
		}
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
			authz, err := getAuthorizationIDsByDomain(ssa.dbMap, table, identifier, now)
			if err != nil {
				return results[0], results[1], err
			}
			numAuthz := len(authz)
			if numAuthz == 0 {
				break
			}

			numRevoked, err := revokeAuthorizations(ssa.dbMap, table, authz)
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
func (ssa *SQLStorageAuthority) AddCertificate(ctx context.Context, certDER []byte, regID int64, ocspResponse []byte) (string, error) {
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
		Issued:         ssa.clk.Now(),
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

	// Note: will fail on duplicate serials. Extremely unlikely to happen and soon
	// to be fixed by redesign. Reference issue
	// https://github.com/letsencrypt/boulder/issues/2265 for more
	err = tx.Insert(cert)
	if err != nil {
		return "", Rollback(tx, err)
	}

	err = tx.Insert(certStatus)
	if err != nil {
		return "", Rollback(tx, err)
	}

	err = addIssuedNames(tx, parsedCertificate)
	if err != nil {
		return "", Rollback(tx, err)
	}

	err = addFQDNSet(
		tx,
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

// CountCertificatesRange returns the number of certificates issued in a specific
// date range
func (ssa *SQLStorageAuthority) CountCertificatesRange(ctx context.Context, start, end time.Time) (int64, error) {
	var count int64
	err := ssa.dbMap.SelectOne(
		&count,
		`SELECT COUNT(1) FROM certificates
		WHERE issued >= :windowLeft
		AND issued < :windowRight`,
		map[string]interface{}{
			"windowLeft":  start,
			"windowRight": end,
		},
	)
	return count, err
}

// CountPendingAuthorizations returns the number of pending, unexpired
// authorizations for the given registration.
func (ssa *SQLStorageAuthority) CountPendingAuthorizations(ctx context.Context, regID int64) (count int, err error) {
	err = ssa.dbMap.SelectOne(&count,
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

// CountPendingOrders returns the number of pending, unexpired
// orders for the given registration.
func (ssa *SQLStorageAuthority) CountPendingOrders(ctx context.Context, regID int64) (int, error) {
	var count int
	err := ssa.dbMap.SelectOne(&count,
		`SELECT count(1) FROM orders
		WHERE registrationID = :regID AND
		expires > :now AND
		status = :pending`,
		map[string]interface{}{
			"regID":   regID,
			"now":     ssa.clk.Now(),
			"pending": string(core.StatusPending),
		})
	return count, err
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
	err = ssa.dbMap.SelectOne(count.Count,
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

// ErrNoReceipt is an error type for non-existent SCT receipt
type ErrNoReceipt string

func (e ErrNoReceipt) Error() string {
	return string(e)
}

// GetSCTReceipt gets a specific SCT receipt for a given certificate serial and
// CT log ID
func (ssa *SQLStorageAuthority) GetSCTReceipt(ctx context.Context, serial string, logID string) (core.SignedCertificateTimestamp, error) {
	receipt, err := selectSctReceipt(ssa.dbMap, "WHERE certificateSerial = ? AND logID = ?", serial, logID)
	if err == sql.ErrNoRows {
		return receipt, ErrNoReceipt(err.Error())
	}
	return receipt, err
}

// AddSCTReceipt adds a new SCT receipt to the (append-only) sctReceipts table
func (ssa *SQLStorageAuthority) AddSCTReceipt(ctx context.Context, sct core.SignedCertificateTimestamp) error {
	err := ssa.dbMap.Insert(&sct)
	// For AddSCTReceipt, duplicates are explicitly OK, so don't return errors
	// based on duplicates, especially because we currently retry all submissions
	// for a certificate if even one of them fails. Once https://github.com/letsencrypt/boulder/issues/891
	// is fixed, we may want to start returning this as an error, or logging it.
	if err != nil && strings.HasPrefix(err.Error(), "Error 1062: Duplicate entry") {
		return nil
	}
	return err
}

func hashNames(names []string) []byte {
	names = core.UniqueLowerNames(names)
	hash := sha256.Sum256([]byte(strings.Join(names, ",")))
	return hash[:]
}

func addFQDNSet(tx *gorp.Transaction, names []string, serial string, issued time.Time, expires time.Time) error {
	return tx.Insert(&core.FQDNSet{
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
	tx *gorp.Transaction,
	names []string,
	orderID int64,
	regID int64,
	expires time.Time) error {
	return tx.Insert(&orderFQDNSet{
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
	tx *gorp.Transaction,
	orderID int64) error {

	result, err := tx.Exec(`
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

type execable interface {
	Exec(string, ...interface{}) (sql.Result, error)
}

func addIssuedNames(tx execable, cert *x509.Certificate) error {
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
	_, err := tx.Exec(query, values...)
	return err
}

// CountFQDNSets returns the number of sets with hash |setHash| within the window
// |window|
func (ssa *SQLStorageAuthority) CountFQDNSets(ctx context.Context, window time.Duration, names []string) (int64, error) {
	var count int64
	err := ssa.dbMap.SelectOne(
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
func (ssa *SQLStorageAuthority) getFQDNSetsBySerials(serials []string) ([]setHash, error) {
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
	_, err := ssa.dbMap.Select(
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
func (ssa *SQLStorageAuthority) getNewIssuancesByFQDNSet(fqdnSets []setHash, earliest time.Time) (int, error) {
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
	_, err := ssa.dbMap.Select(
		&results,
		query,
		params...)
	if err != nil && err != sql.ErrNoRows {
		return -1, err
	}

	// If there are no results we have encountered a major error and
	// should loudly complain
	if err == sql.ErrNoRows || len(results) == 0 {
		ssa.log.AuditErr(fmt.Sprintf("Found no results from fqdnSets for setHashes known to exist: %#v", fqdnSets))
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
	err := ssa.dbMap.SelectOne(
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
	err := ssa.dbMap.SelectOne(
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
	err = ssa.dbMap.SelectOne(
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
	_, err := ssa.dbMap.Exec(
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
	table := authorizationTable
	oldStatus := core.StatusValid
	if existingPending(tx, id) {
		table = pendingAuthorizationTable
		oldStatus = core.StatusPending
	}

	_, err = tx.Exec(
		fmt.Sprintf(`UPDATE %s SET status = ? WHERE id = ? and status = ?`, table),
		string(core.StatusDeactivated),
		id,
		string(oldStatus),
	)
	if err != nil {
		err = Rollback(tx, err)
		return err
	}
	return tx.Commit()
}

// NewOrder adds a new v2 style order to the database
func (ssa *SQLStorageAuthority) NewOrder(ctx context.Context, req *corepb.Order) (*corepb.Order, error) {
	order := &orderModel{
		RegistrationID: *req.RegistrationID,
		Expires:        time.Unix(0, *req.Expires),
		Status:         core.AcmeStatus(*req.Status),
	}

	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return nil, err
	}

	if err := tx.Insert(order); err != nil {
		return nil, Rollback(tx, err)
	}

	for _, id := range req.Authorizations {
		otoa := &orderToAuthzModel{
			OrderID: order.ID,
			AuthzID: id,
		}
		if err := tx.Insert(otoa); err != nil {
			return nil, Rollback(tx, err)
		}
	}

	for _, name := range req.Names {
		reqdName := &requestedNameModel{
			OrderID:      order.ID,
			ReversedName: ReverseName(name),
		}
		if err := tx.Insert(reqdName); err != nil {
			return nil, Rollback(tx, err)
		}
	}

	// Add an FQDNSet entry for the order
	if err := addOrderFQDNSet(
		tx, req.Names, order.ID, order.RegistrationID, order.Expires); err != nil {
		return nil, Rollback(tx, err)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	// Update the request with the ID that the order received
	req.Id = &order.ID
	return req, nil
}

// SetOrderProcessing updates a provided *corepb.Order in pending status to be
// in processing status by updating the status field of the corresponding Order
// table row in the DB. We avoid introducing a general purpose "Update this
// order" RPC to ensure we have minimally permissive RPCs.
func (ssa *SQLStorageAuthority) SetOrderProcessing(ctx context.Context, req *corepb.Order) error {
	tx, err := ssa.dbMap.Begin()
	if err != nil {
		return err
	}

	result, err := tx.Exec(`
		UPDATE orders
		SET status = ?
		WHERE id = ?
		AND status = ?`,
		string(core.StatusProcessing),
		*req.Id,
		string(core.StatusPending))
	if err != nil {
		err = berrors.InternalServerError("error updating order to processing status")
		return Rollback(tx, err)
	}

	n, err := result.RowsAffected()
	if err != nil || n == 0 {
		err = berrors.InternalServerError("no order updated to processing status")
		return Rollback(tx, err)
	}

	return tx.Commit()
}

// setOrderInvalid updates a provided *corepb.Order in pending status to be in
// invalid status by updating the status field of the corresponding row in the
// DB.
func (ssa *SQLStorageAuthority) setOrderInvalid(ctx context.Context, tx *gorp.Transaction, req *corepb.Order) error {
	result, err := tx.Exec(`
		UPDATE orders
		SET status = ?
		WHERE id = ?
		AND status = ?`,
		string(core.StatusInvalid),
		*req.Id,
		string(core.StatusPending))
	if err != nil {
		return err
	}

	n, err := result.RowsAffected()
	if err != nil || n == 0 {
		return berrors.InternalServerError("no order updated to invalid status")
	}
	return nil
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

	result, err := tx.Exec(`
		UPDATE orders
		SET certificateSerial = ?, status = ?
		WHERE id = ?
		AND status = ?`,
		*req.CertificateSerial,
		string(core.StatusValid),
		*req.Id,
		string(core.StatusProcessing))
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
	if err := deleteOrderFQDNSet(tx, *req.Id); err != nil {
		return Rollback(tx, err)
	}

	return tx.Commit()
}

func (ssa *SQLStorageAuthority) authzForOrder(orderID int64) ([]string, error) {
	var ids []string
	_, err := ssa.dbMap.Select(&ids, "SELECT authzID FROM orderToAuthz WHERE orderID = ?", orderID)
	if err != nil {
		return nil, err
	}
	return ids, nil
}

// orderForAuthz finds an order ID associated with a given authz (If any).
func (ssa *SQLStorageAuthority) orderIDForAuthz(tx *gorp.Transaction, authzID string) (int64, error) {
	var orderID int64

	err := tx.SelectOne(&orderID, `
	SELECT orderID
	FROM orderToAuthz
	WHERE authzID = ?`,
		authzID)

	// NOTE(@cpu): orderIDForAuthz does not handle the sql.ErrNoRows that could be
	// returned by `SelectOne`. The caller must do so.
	if err != nil {
		// If there is an err, return it as-is.
		return 0, err
	}

	return orderID, nil
}

// namesForOrder finds all of the requested names associated with an order. The
// names are returned in their reversed form (see `sa.ReverseName`).
func (ssa *SQLStorageAuthority) namesForOrder(orderID int64) ([]string, error) {
	var reversedNames []string
	_, err := ssa.dbMap.Select(&reversedNames, `
	SELECT reversedName
	FROM requestedNames
	WHERE orderID = ?`, orderID)
	if err != nil {
		return nil, err
	}
	return reversedNames, nil
}

// GetOrder is used to retrieve an already existing order object
func (ssa *SQLStorageAuthority) GetOrder(ctx context.Context, req *sapb.OrderRequest) (*corepb.Order, error) {
	omObj, err := ssa.dbMap.Get(orderModel{}, *req.Id)
	if err == sql.ErrNoRows || omObj == nil {
		return nil, berrors.NotFoundError("no order found for ID %d", *req.Id)
	}
	if err != nil {
		return nil, err
	}
	order := modelToOrder(omObj.(*orderModel))
	authzIDs, err := ssa.authzForOrder(*order.Id)
	if err != nil {
		return nil, err
	}
	for _, authzID := range authzIDs {
		order.Authorizations = append(order.Authorizations, authzID)
	}

	names, err := ssa.namesForOrder(*order.Id)
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

	return order, nil
}

// GetOrderAuthorizations is used to find the valid, unexpired authorizations
// associated with a specific order and account ID.
func (ssa *SQLStorageAuthority) GetOrderAuthorizations(
	ctx context.Context,
	req *sapb.GetOrderAuthorizationsRequest) (map[string]*core.Authorization, error) {
	now := ssa.clk.Now()
	// Select the full authorization data for all *valid, unexpired*
	// authorizations that are owned by the correct account ID and associated with
	// the given order ID
	var auths []*core.Authorization
	_, err := ssa.dbMap.Select(
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
			if features.Enabled(features.EnforceChallengeDisable) {
				// Retrieve challenges for the authz
				auth.Challenges, err = ssa.getChallenges(auth.ID)
				if err != nil {
					return nil, err
				}
			}

			byName[auth.Identifier.Value] = auth
		}
	}
	return byName, nil
}

// GetOrderForNames tries to find an order with the exact set of names
// requested, associated with the given accountID. Only unexpired orders are
// considered. If no order is found a nil corepb.Order pointer is returned.
func (ssa *SQLStorageAuthority) GetOrderForNames(
	ctx context.Context,
	req *sapb.GetOrderForNamesRequest) (*corepb.Order, error) {

	// Hash the names requested for lookup in the orderFqdnSets table
	fqdnHash := hashNames(req.Names)

	var orderID int64
	err := ssa.dbMap.SelectOne(&orderID, `
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

func (ssa *SQLStorageAuthority) getAuthorizations(ctx context.Context, table string, status string,
	registrationID int64, names []string, now time.Time) (map[string]*core.Authorization, error) {
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

	var auths []*core.Authorization
	_, err := ssa.dbMap.Select(
		&auths,
		fmt.Sprintf(`SELECT %s FROM %s
	WHERE registrationID = ? AND
	expires > ? AND
	status = ? AND
	identifier IN (%s)`, authzFields, table, strings.Join(qmarks, ",")),
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
			if features.Enabled(features.EnforceChallengeDisable) {
				// Retrieve challenges for the authz
				auth.Challenges, err = ssa.getChallenges(auth.ID)
				if err != nil {
					return nil, err
				}
			}

			byName[auth.Identifier.Value] = auth
		}
	}

	return byName, nil
}

func (ssa *SQLStorageAuthority) getPendingAuthorizations(ctx context.Context, registrationID int64, names []string, now time.Time) (map[string]*core.Authorization, error) {
	return ssa.getAuthorizations(ctx, pendingAuthorizationTable, string(core.StatusPending), registrationID, names, now)
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
func (ssa *SQLStorageAuthority) GetAuthorizations(ctx context.Context, req *sapb.GetAuthorizationsRequest) (*sapb.Authorizations, error) {
	authzMap, err := ssa.getAuthorizations(
		ctx,
		authorizationTable,
		string(core.StatusValid),
		*req.RegistrationID,
		req.Domains,
		time.Unix(0, *req.Now),
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
	pendingAuthz, err := ssa.getPendingAuthorizations(ctx, *req.RegistrationID, remainingNames, time.Unix(0, *req.Now))
	if err != nil {
		return nil, err
	}
	// merge pending into valid
	for name, a := range pendingAuthz {
		authzMap[name] = a
	}

	// WildcardDomain issuance requires that the authorizations returned by this
	// RPC also include populated challenges such that the caller can know if the
	// challenges meet the wildcard issuance policy (e.g. only 1 DNS-01
	// challenge). We use a feature flag check here in case this causes
	// performance regressions.
	if features.Enabled(features.WildcardDomains) {
		// Fetch each of the authorizations' associated challenges
		for _, authz := range authzMap {
			authz.Challenges, err = ssa.getChallenges(authz.ID)
		}
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

func (ssa *SQLStorageAuthority) getChallenges(authID string) ([]core.Challenge, error) {
	var challObjs []challModel
	_, err := ssa.dbMap.Select(
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
