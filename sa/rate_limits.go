package sa

import (
	"database/sql"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/features"
	"golang.org/x/net/context"
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

func (ssa *SQLStorageAuthority) addCertificatesPerName(
	ctx context.Context,
	db dbSelectExecer,
	names []string,
	timeToTheHour time.Time,
) error {
	if !features.Enabled(features.FasterRateLimit) {
		return nil
	}
	// This maps from a base domain to the issuance count that it should have
	// for this hour.
	baseDomainsMap := map[string]int{}
	var baseDomains []interface{}
	var qmarks []string
	for _, name := range names {
		base := baseDomain(name)
		if baseDomainsMap[base] == 0 {
			baseDomainsMap[base] = 1
			baseDomains = append(baseDomains, base)
			qmarks = append(qmarks, "?")
		}
	}

	// Look up any existing entries and add their counts to the total.
	type nameAndCount struct {
		ETLDPlusOne string
		Count       int
	}
	var counts []nameAndCount
	_, err := db.Select(
		&counts,
		`SELECT eTLDPlusOne, count
		 FROM certificatesPerName
		 WHERE time = ?
		 AND eTLDPlusOne IN (`+strings.Join(qmarks, ", ")+`)`,
		append([]interface{}{timeToTheHour}, baseDomains...)...)
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	for _, c := range counts {
		baseDomainsMap[c.ETLDPlusOne] += c.Count
	}

	// Write out the resulting counts.
	var outputQmarks []string
	var values []interface{}
	for base, count := range baseDomainsMap {
		values = append(values, base, count, timeToTheHour)
		outputQmarks = append(outputQmarks, "(?, ?, ?)")
	}
	_, err = db.Exec(`REPLACE INTO certificatesPerName (eTLDPlusOne, count, time)
					   VALUES `+strings.Join(outputQmarks, ", ")+`;`,
		values...)
	if err != nil {
		return err
	}

	return nil
}

// countCertificatesFaster returns, for a single domain, the count of
// certificates issued in the given time range for that domain's eTLD+1 (aka
// base domain). It uses the certificatesPerName table to make this lookup fast.
// This functioncan replace both countCertificatesByName and
// countCertificatesByExactName because domains that are exactly equal to an
// public suffix have their issuances counted under a separate bucket from their
// subdomains.
func (ssa *SQLStorageAuthority) countCertificatesFaster(
	db dbSelector,
	domain string,
	earliest,
	latest time.Time,
) (int, error) {
	base := baseDomain(domain)
	var counts []int
	_, err := db.Select(
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
	if err == sql.ErrNoRows {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	var total int
	for _, count := range counts {
		total += count
	}
	return total, nil
}
