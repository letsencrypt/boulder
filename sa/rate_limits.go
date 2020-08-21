package sa

import (
	"context"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/db"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

// baseDomain returns the eTLD+1 of a domain name for the purpose of rate
// limiting. For a domain name that is itself an eTLD, it returns its input.
func baseDomain(name string) string {
	eTLDPlusOne, err := publicsuffix.Domain(name)
	if err != nil {
		// publicsuffix.Domain will return an error if the input name is itself a
		// public suffix. In that case we use the input name as the key for rate
		// limiting. Since all of its subdomains will have separate keys for rate
		// limiting (e.g. "foo.bar.publicsuffix.com" will have
		// "bar.publicsuffix.com", this means that domains exactly equal to a
		// public suffix get their own rate limit bucket. This is important
		// because otherwise they might be perpetually unable to issue, assuming
		// the rate of issuance from their subdomains was high enough.
		return name
	}
	return eTLDPlusOne
}

// addCertificatesPerName adds 1 to the rate limit count for the provided domains,
// in a specific time bucket. It must be executed in a transaction, and the
// input timeToTheHour must be a time rounded to an hour.
func (ssa *SQLStorageAuthority) addCertificatesPerName(
	ctx context.Context,
	db db.SelectExecer,
	names []string,
	timeToTheHour time.Time,
) error {
	// De-duplicate the base domains.
	baseDomainsMap := make(map[string]bool)
	var qmarks []string
	var values []interface{}
	for _, name := range names {
		base := baseDomain(name)
		if !baseDomainsMap[base] {
			baseDomainsMap[base] = true
			values = append(values, base, timeToTheHour, 1)
			qmarks = append(qmarks, "(?, ?, ?)")
		}
	}

	_, err := db.Exec(`INSERT INTO certificatesPerName (eTLDPlusOne, time, count) VALUES `+
		strings.Join(qmarks, ", ")+` ON DUPLICATE KEY UPDATE count=count+1;`,
		values...)
	if err != nil {
		return err
	}

	return nil
}

// countCertificates returns, for a single domain, the count of
// certificates issued in the given time range for that domain's eTLD+1 (aka
// base domain). It uses the certificatesPerName table to make this lookup fast.
func (ssa *SQLStorageAuthority) countCertificates(
	dbMap db.Selector,
	domain string,
	earliest,
	latest time.Time,
) (int, error) {
	base := baseDomain(domain)
	var counts []int
	_, err := dbMap.Select(
		&counts,
		`SELECT count FROM certificatesPerName
		 WHERE eTLDPlusOne = :baseDomain AND
		 time > :earliest AND
		 time <= :latest`,
		map[string]interface{}{
			"baseDomain": base,
			"earliest":   earliest,
			"latest":     latest,
		})
	if err != nil {
		if db.IsNoRows(err) {
			return 0, nil
		}
		return 0, err
	}
	var total int
	for _, count := range counts {
		total += count
	}
	return total, nil
}

// addNewOrdersRateLimit adds 1 to the rate limit count for the provided ID,
// in a specific time bucket. It must be executed in a transaction, and the
// input timeToTheMinute must be a time rounded to a minute.
func addNewOrdersRateLimit(ctx context.Context, dbMap db.SelectExecer, regID int64, timeToTheMinute time.Time) error {
	_, err := dbMap.Exec(`INSERT INTO newOrdersRL
		(regID, time, count)
		VALUES (?, ?, 1)
		ON DUPLICATE KEY UPDATE count=count+1;`,
		regID,
		timeToTheMinute,
	)
	if err != nil {
		return err
	}
	return nil
}

// countNewOrders returns the count of orders created in the given time range
// for the given registration ID
func countNewOrders(ctx context.Context, dbMap db.Selector, regID int64, earliest, latest time.Time) (int, error) {
	var counts []int
	_, err := dbMap.Select(
		&counts,
		`SELECT count FROM newOrdersRL
		WHERE regID = :regID AND
		time > :earliest AND
		time <= :latest`,
		map[string]interface{}{
			"regID":    regID,
			"earliest": earliest,
			"latest":   latest,
		},
	)
	if err != nil {
		if db.IsNoRows(err) {
			return 0, nil
		}
		return 0, err
	}
	var total int
	for _, count := range counts {
		total += count
	}
	return total, nil
}
