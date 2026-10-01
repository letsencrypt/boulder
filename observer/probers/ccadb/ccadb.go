package ccadb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/letsencrypt/boulder/crl/checker"
	"github.com/letsencrypt/boulder/crl/idp"
	"github.com/letsencrypt/boulder/observer/probers"
	"github.com/letsencrypt/boulder/strictyaml"
)

// CCADBConf is exported to receive YAML configuration.
type CCADBConf struct {
	AllCertificatesCSVURL string `yaml:"allCertificatesCSVURL"`
	CertificatePEMsURL    string `yaml:"certificatePEMsURL"`
	CAOwner               string `yaml:"caOwner"`
	CRLAgeLimit           string `yaml:"crlAgeLimit"`
	// CRLRegexp is the regex used for parsing CRL URLs. It must strictly check
	// the validity of a given CRL URL. It must also specify a capture group
	// named crlNumber, which is the CRL shard index.
	//
	// Because this prober fetches URLs controlled by external input (CCADB), we
	// rely on this regexp avoid arbitrary content fetching (SSRF).
	CRLRegexp string `yaml:"crlRegexp"`
	// CACRLAgeLimit is the age limit for CRLs covering CA certificates, i.e.
	// those issued by our roots. These are issued far less often than the
	// partitioned CRLs covering Subscriber certificates.
	CACRLAgeLimit string `yaml:"caCRLAgeLimit"`
	// CACRLRegexp is the regex used to validate CA CRL URLs before fetching
	// them. Like CRLRegexp, it must strictly check the validity of a given URL.
	CACRLRegexp string `yaml:"caCRLRegexp"`
}

// Kind returns a name that uniquely identifies the `Kind` of `Configurer`.
func (c CCADBConf) Kind() string {
	return "CCADB"
}

// UnmarshalSettings takes YAML as bytes and unmarshals it to a CCADBConf object.
func (c CCADBConf) UnmarshalSettings(settings []byte) (probers.Configurer, error) {
	var conf CCADBConf
	err := strictyaml.Unmarshal(settings, &conf)
	if err != nil {
		return nil, err
	}

	return conf, nil
}

// MakeProber constructs a `CCADBProbe` object from the contents of the bound
// `CCADBConf` object. If the `CCADBConf` cannot be validated, an error appropriate
// for end-user consumption is returned instead.
func (c CCADBConf) MakeProber(collectors map[string]prometheus.Collector) (probers.Prober, error) {
	// See https://www.ccadb.org/resources for these URLs.
	ccadbAllCertificatesCSVURL := "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv5"
	if c.AllCertificatesCSVURL != "" {
		ccadbAllCertificatesCSVURL = c.AllCertificatesCSVURL
	}

	certificatePEMsURL := "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificatePEMsCSVFormat"
	if c.CertificatePEMsURL != "" {
		certificatePEMsURL = c.CertificatePEMsURL
	}

	caOwner := "Internet Security Research Group"
	if c.CAOwner != "" {
		caOwner = c.CAOwner
	}

	ageLimitDuration := 24 * time.Hour
	if c.CRLAgeLimit != "" {
		var err error
		ageLimitDuration, err = time.ParseDuration(c.CRLAgeLimit)
		if err != nil {
			return nil, fmt.Errorf("parsing age limit: %s", err)
		}
	}

	crlRegexp := `^http://[a-z0-9-]+\.c\.lencr\.org/(?P<crlNumber>\d+)\.crl$`
	if c.CRLRegexp != "" {
		crlRegexp = c.CRLRegexp
	}

	re, err := regexp.Compile(crlRegexp)
	if err != nil {
		return nil, fmt.Errorf("parsing CRL regexp %q: %s", crlRegexp, err)
	}

	// Root CRLs are reissued at least every 12 months, per BRs 4.9.7.
	caCRLAgeLimit := 365 * 24 * time.Hour
	if c.CACRLAgeLimit != "" {
		caCRLAgeLimit, err = time.ParseDuration(c.CACRLAgeLimit)
		if err != nil {
			return nil, fmt.Errorf("parsing CA CRL age limit: %s", err)
		}
	}

	caCRLRegexp := `^http://[a-z0-9-]+\.c\.lencr\.org/$`
	if c.CACRLRegexp != "" {
		caCRLRegexp = c.CACRLRegexp
	}

	caRe, err := regexp.Compile(caCRLRegexp)
	if err != nil {
		return nil, fmt.Errorf("parsing CA CRL regexp %q: %s", caCRLRegexp, err)
	}

	return &CCADBProber{
		allCertificatesCSVURL: ccadbAllCertificatesCSVURL,
		certificatePEMsURL:    certificatePEMsURL,
		caOwner:               caOwner,
		crlAgeLimit:           ageLimitDuration,
		crlRegexp:             re,
		caCRLAgeLimit:         caCRLAgeLimit,
		caCRLRegexp:           caRe,
	}, nil
}

// Instrument constructs any `prometheus.Collector` objects the `CCADBProber` will
// need to report its own metrics. A map is returned containing the constructed
// objects, indexed by the name of the Prometheus metric.  If no objects were
// constructed, nil is returned.
func (c CCADBConf) Instrument() map[string]prometheus.Collector {
	return nil
}

func getIDP(crl *x509.RevocationList) (string, error) {
	idps, err := idp.GetIDPURIs(crl.Extensions)
	if err != nil {
		return "", fmt.Errorf("extracting IssuingDistributionPoint URIs: %v", err)
	}
	if len(idps) == 1 {
		return idps[0], nil
	}
	return "", fmt.Errorf("CRL had incorrect number of IssuingDistributionPoint URIs: %s", idps)
}

// CCADBProber checks the CRLs we report in CCADB for correctness.
//
// It determines the CRLs in scope by fetching the AllCertificatesRecordsReport
// from CCADB, and filtering for a specific CA Owner (defaults to 'Internet
// Security Research Group').
//
// It checks that the CRLs:
//   - Are not too old
//   - Have an issuingDistributionPoint that matches the URL from which they
//     were fetched
//   - Have a valid signature based on their issuer SKID from CCADB
//   - Don't have duplicate serial numbers across different CRLs
//
// It also checks, heuristically, whether the complete corpus of CRL shards
// are reported in CCADB.
//
// For CAs that issue CA certificates (our roots), it checks that the CRL URLs
// disclosed for them exactly match the CRLDPs in the unexpired CA certificates
// they issued, and that each disclosed CRL is fresh and correctly signed.
type CCADBProber struct {
	allCertificatesCSVURL string
	certificatePEMsURL    string
	caOwner               string
	crlAgeLimit           time.Duration
	crlRegexp             *regexp.Regexp
	caCRLAgeLimit         time.Duration
	caCRLRegexp           *regexp.Regexp
}

func (c CCADBProber) Kind() string {
	return "CCADB"
}

func (c CCADBProber) Name() string {
	return "CCADB"
}

func (c *CCADBProber) Probe(ctx context.Context) error {
	records, err := c.getRecords(ctx)
	if err != nil {
		return err
	}

	issuers, certsByFingerprint, err := c.getAllIntermediates(ctx, records)
	if err != nil {
		return err
	}

	crlURLs, err := c.getCRLURLs(records, issuers)
	if err != nil {
		return err
	}

	// Map of serials to their CRL issuingDistributionPoint.
	serials := make(map[string]string)

	var errs []error
	for skid, urls := range crlURLs {
		issuer := issuers[skid]
		if issuer == nil {
			errs = append(errs, fmt.Errorf("no issuer found for skid %x", skid))
			continue
		}

		var (
			seenCRLShardIndices []int
			exampleCRLShardURL  string
		)
		for _, url := range urls {
			// This can happen when an issuer is not yet issuing.
			if url == "" {
				continue
			}

			matches := c.crlRegexp.FindAllStringSubmatch(url, 2)
			if matches == nil {
				errs = append(errs, fmt.Errorf("CRL %s does not match regexp %s", url, c.crlRegexp))
				continue
			}
			match := matches[0]
			if len(match) != 2 {
				errs = append(errs, fmt.Errorf("CRL %s does not match regexp %s", url, c.crlRegexp))
				continue
			}
			crlNumber, err := strconv.Atoi(match[1])
			if err != nil {
				errs = append(errs, fmt.Errorf("cannot parse CRL shard number from %s: %s", url, err))
				continue
			}
			seenCRLShardIndices = append(seenCRLShardIndices, crlNumber)
			exampleCRLShardURL = url

			crl, err := checkCRL(ctx, url, issuer, c.crlAgeLimit)
			if err != nil {
				errs = append(errs, fmt.Errorf("fetching %s: %s", url, err))
				continue
			}

			// Check for duplicates across different CRLs (or within a CRL).
			// Cap any given CRL at 1M entries to limit memory use.
			for i, entry := range crl.RevokedCertificateEntries {
				if i > 1_000_000 {
					break
				}
				serialByteString := string(entry.SerialNumber.Bytes())
				if otherCRLURL, ok := serials[serialByteString]; ok {
					errs = append(errs, fmt.Errorf("serial %x seen on multiple CRLs: %s and %s", entry.SerialNumber, otherCRLURL, url))
				}
				serials[serialByteString] = url
			}
		}

		if len(seenCRLShardIndices) > 0 {
			// The max()+1th shard should not be live. This generally occurs if we have
			// live CRL shards that are not reported in CCADB.
			maxShardIndex := slices.Max(seenCRLShardIndices)
			err := checkCRLShardNotFound(ctx, c.crlRegexp, exampleCRLShardURL, maxShardIndex+1)
			if err != nil {
				errs = append(errs, err)
			}

			// The 0th shard should not be live, because shards are 1-indexed.
			err = checkCRLShardNotFound(ctx, c.crlRegexp, exampleCRLShardURL, 0)
			if err != nil {
				errs = append(errs, err)
			}

			// It is possible that the number of CRL shards shrinks, but it is highly
			// unlikely, because we would never have any reason make that so. Therefore
			// we do not detect this case.

			err = checkAllShardIndexesPresent(seenCRLShardIndices)
			if err != nil {
				errs = append(errs, fmt.Errorf("issuer %q: %w", issuer.Subject.CommonName, err))
			}
		}
	}

	errs = append(errs, c.checkCACRLs(ctx, records, issuers, certsByFingerprint)...)

	return errors.Join(errs...)
}

func checkCRL(ctx context.Context, url string, issuer *x509.Certificate, ageLimit time.Duration) (*x509.RevocationList, error) {
	body, err := httpGet(ctx, url)
	if err != nil {
		return nil, err
	}

	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		return nil, err
	}

	idp, err := getIDP(crl)
	if err != nil {
		return nil, err
	}

	if idp != url {
		return nil, fmt.Errorf("CRL fetched from %s had mismatched IDP %s", url, idp)
	}

	return crl, checker.Validate(crl, issuer, ageLimit)
}

// getCSV fetches CSV from a URL and starts a *csv.Reader on it,
// returning the header as []string followed by the *csv.Reader.
func getCSV(ctx context.Context, url string) ([]string, *csv.Reader, error) {
	body, err := httpGet(ctx, url)
	if err != nil {
		return nil, nil, err
	}
	reader := csv.NewReader(bytes.NewReader(body))
	header, err := reader.Read()
	if err != nil {
		return nil, nil, fmt.Errorf("%q: %w", url, err)
	}

	return header, reader, nil
}

func checkCRLShardNotFound(ctx context.Context, re *regexp.Regexp, exampleCRLShardURL string, shardIndex int) error {
	match := re.FindStringSubmatchIndex(exampleCRLShardURL)
	if match == nil || len(match) != 4 || match[2] < 0 {
		return fmt.Errorf("CRL %s does not match regexp %s", exampleCRLShardURL, re)
	}
	// There is mild SSRF risk because this input is derived from CCADB controlled
	// values. This is mitigated by using a stringent regex.
	url := exampleCRLShardURL[:match[2]] + strconv.Itoa(shardIndex) + exampleCRLShardURL[match[3]:]

	err := httpGetExpectingStatusCode(ctx, url, http.StatusNotFound)
	if err != nil {
		return fmt.Errorf("did not get expected status 404 for %s: %w", url, err)
	}
	return nil
}

// checkAllShardIndexesPresent returns an error naming any index in
// [1..max(seen)] that is absent from seen.
func checkAllShardIndexesPresent(seen []int) error {
	if len(seen) == 0 {
		return nil
	}
	seenSet := make(map[int]struct{}, len(seen))
	for _, index := range seen {
		seenSet[index] = struct{}{}
	}
	var missing []int
	maxIndex := slices.Max(seen)
	if maxIndex > 100_000 {
		// Avoid unbounded allocation via typos in CCADB, e.g. 99999999.crl
		return fmt.Errorf("CRL corpus is unexpectedly large: %d", maxIndex)
	}
	for i := 1; i <= maxIndex; i++ {
		_, ok := seenSet[i]
		if !ok {
			missing = append(missing, i)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("CRL shard indexes %v not reported in CCADB", missing)
	}
	return nil
}

// getAllIntermediates returns the certificates for the given records, keyed by
// SKID and by fingerprint (see getDecadeIntermediates).
func (c CCADBProber) getAllIntermediates(ctx context.Context, records []ccadbRecord) (map[string]*x509.Certificate, map[string]*x509.Certificate, error) {
	wanted := make(map[string]bool, len(records))
	for _, record := range records {
		wanted[record.fingerprint] = true
	}

	bySKID, byFingerprint, err := c.getDecadeIntermediates(ctx, 2010, wanted)
	if err != nil {
		return nil, nil, err
	}

	moreBySKID, moreByFingerprint, err := c.getDecadeIntermediates(ctx, 2020, wanted)
	if err != nil {
		return nil, nil, err
	}

	maps.Copy(bySKID, moreBySKID)
	maps.Copy(byFingerprint, moreByFingerprint)
	return bySKID, byFingerprint, nil
}

// getDecadeIntermediates returns the certificates in the given decade's PEM
// report whose fingerprints are in wanted, twice: keyed by SKID, and keyed by
// uppercase hex SHA-256 fingerprint (the format CCADB uses in its "SHA-256
// Fingerprint" columns). The SKID map collapses cross-signs of the same key
// into one entry; the fingerprint map does not.
//
// The report covers every CA Owner (thousands of certificates), and we only
// need our own, so we skip parsing and retaining the rest to save memory.
func (c CCADBProber) getDecadeIntermediates(ctx context.Context, decade int, wanted map[string]bool) (map[string]*x509.Certificate, map[string]*x509.Certificate, error) {
	url := fmt.Sprintf("%s?NotBeforeDecade=%d", c.certificatePEMsURL, decade)
	header, reader, err := getCSV(ctx, url)
	if err != nil {
		return nil, nil, err
	}

	pemIndex := slices.Index(header, "X.509 Certificate (PEM)")
	if pemIndex == -1 {
		return nil, nil, fmt.Errorf("no column named \"X.509 Certificate (PEM)\" in %s", url)
	}

	bySKID := make(map[string]*x509.Certificate)
	byFingerprint := make(map[string]*x509.Certificate)
	var numPEMs int
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("%q: %w", url, err)
		}

		if len(record) < pemIndex {
			continue
		}

		block, _ := pem.Decode([]byte(record[pemIndex]))
		if block == nil {
			continue
		}
		numPEMs++

		sum := sha256.Sum256(block.Bytes)
		fingerprint := strings.ToUpper(hex.EncodeToString(sum[:]))
		if !wanted[fingerprint] {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		bySKID[string(cert.SubjectKeyId)] = cert
		byFingerprint[fingerprint] = cert
	}

	if numPEMs == 0 {
		return nil, nil, fmt.Errorf("no valid certificate PEMs found in %s", url)
	}
	return bySKID, byFingerprint, nil
}

// ccadbRecord is the subset of a row of the All Certificate Records report
// that this prober uses.
type ccadbRecord struct {
	name string
	// skid is the raw (not base64) Subject Key Identifier.
	skid string
	// fingerprint and parentFingerprint are uppercase hex SHA-256.
	fingerprint       string
	parentFingerprint string
	revocationStatus  string
	// partitionedCRLs and fullCRLs are nil when the column is empty.
	partitionedCRLs []string
	fullCRLs        []string
}

// getRecords fetches the All Certificate Records report and returns the rows
// belonging to our CA Owner.
func (c CCADBProber) getRecords(ctx context.Context) ([]ccadbRecord, error) {
	header, reader, err := getCSV(ctx, c.allCertificatesCSVURL)
	if err != nil {
		return nil, err
	}

	const (
		owner             = "CA Owner"
		certificateName   = "Certificate Name"
		skid              = "Subject Key Identifier"
		fingerprint       = "SHA-256 Fingerprint"
		parentFingerprint = "Parent SHA-256 Fingerprint"
		revocationStatus  = "Revocation Status"
		partitionedCRLs   = "JSON Array of Partitioned CRLs"
		fullCRLs          = "JSON Array of All Full CRL URLs"
	)

	columns := map[string]int{}
	for _, headerName := range []string{owner, certificateName, skid, fingerprint, parentFingerprint, revocationStatus, partitionedCRLs, fullCRLs} {
		index := slices.Index(header, headerName)
		if index == -1 {
			return nil, fmt.Errorf("no column named %q in %s", headerName, c.allCertificatesCSVURL)
		}
		columns[headerName] = index
	}

	parseURLs := func(name, column, value string) ([]string, error) {
		if value == "" {
			return nil, nil
		}
		var urls []string
		err := json.Unmarshal([]byte(value), &urls)
		if err != nil {
			return nil, fmt.Errorf("parsing %q for %q: %w", column, name, err)
		}
		return urls, nil
	}

	var records []ccadbRecord
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%q: %w", c.allCertificatesCSVURL, err)
		}
		if row[columns[owner]] != c.caOwner {
			continue
		}

		name := row[columns[certificateName]]
		skid, err := base64.StdEncoding.DecodeString(row[columns[skid]])
		if err != nil {
			return nil, err
		}
		partitioned, err := parseURLs(name, partitionedCRLs, row[columns[partitionedCRLs]])
		if err != nil {
			return nil, err
		}
		full, err := parseURLs(name, fullCRLs, row[columns[fullCRLs]])
		if err != nil {
			return nil, err
		}

		records = append(records, ccadbRecord{
			name:              name,
			skid:              string(skid),
			fingerprint:       strings.ToUpper(row[columns[fingerprint]]),
			parentFingerprint: strings.ToUpper(row[columns[parentFingerprint]]),
			revocationStatus:  row[columns[revocationStatus]],
			partitionedCRLs:   partitioned,
			fullCRLs:          full,
		})
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no records found in CCADB for CA Owner %q", c.caOwner)
	}
	return records, nil
}

// returns a map from issuer SKID to list of URLs
func (c CCADBProber) getCRLURLs(records []ccadbRecord, issuers map[string]*x509.Certificate) (map[string][]string, error) {
	allCRLs := make(map[string][]string)
	for _, record := range records {
		crls := record.partitionedCRLs
		if crls == nil {
			continue
		}
		if len(record.skid) == 0 {
			return nil, fmt.Errorf("no skid for %q", record.name)
		}
		if issuers[record.skid] == nil {
			return nil, fmt.Errorf("CCADB contained %q with SKID %x, but that SKID is not in issuers CRL at %s?decade=XXXX",
				record.name, record.skid, c.certificatePEMsURL)
		}
		// An issuer can show up multiple times, under different cross-signs. However,
		// it must have the same list of CRLs each time.
		if c := allCRLs[record.skid]; c != nil && !slices.Equal(c, crls) {
			return nil, fmt.Errorf("CCADB contained %q with SKID %x multiple times with different CRLs", record.name, record.skid)
		}
		allCRLs[record.skid] = crls
	}

	if len(allCRLs) == 0 {
		return nil, fmt.Errorf("no records found in CCADB for CA Owner %q", c.caOwner)
	}
	return allCRLs, nil
}

// checkCACRLs checks the CRL disclosures for CAs that issue CA certificates,
// i.e. our roots and their cross-signs. CCADB has these in the "All Full CRL
// URLs" column; we treat every record without partitioned CRLs as one.
//
// CCADB Policy 6.2 requires that the disclosed URLs exactly match the distinct
// HTTP URLs in the crlDistributionPoints of the unexpired certificates issued
// by that CA. Everything a root issues is itself disclosed in CCADB, so we
// compute that set from the certificates directly, rather than assuming it
// from our own configuration. Each disclosed URL is also fetched and checked.
func (c CCADBProber) checkCACRLs(ctx context.Context, records []ccadbRecord, bySKID, byFingerprint map[string]*x509.Certificate) []error {
	var errs []error
	now := time.Now()

	skidByFingerprint := make(map[string]string, len(records))
	for _, record := range records {
		skidByFingerprint[record.fingerprint] = record.skid
	}

	// The set of CRLDPs in unexpired certificates issued by each CA, keyed by
	// the CA's SKID. A CA can have several records (e.g. self-signed and
	// cross-signed) but the requirement applies to the CA, so we group by key.
	// Revoked certificates are included, since the policy only excludes
	// expired ones.
	wantBySKID := make(map[string]map[string]struct{})
	for _, record := range records {
		issuerSKID, ok := skidByFingerprint[record.parentFingerprint]
		if !ok {
			// A root, or issued by another CA Owner.
			continue
		}
		cert := byFingerprint[record.fingerprint]
		if cert == nil {
			errs = append(errs, fmt.Errorf("no PEM found in CCADB for %q (%s)", record.name, record.fingerprint))
			continue
		}
		if now.After(cert.NotAfter) {
			continue
		}
		if wantBySKID[issuerSKID] == nil {
			wantBySKID[issuerSKID] = make(map[string]struct{})
		}
		for _, crldp := range cert.CRLDistributionPoints {
			if strings.HasPrefix(crldp, "http://") {
				wantBySKID[issuerSKID][crldp] = struct{}{}
			}
		}
	}

	type disclosure struct{ skid, url string }
	var toFetch []disclosure
	seen := make(map[disclosure]bool)

	for _, record := range records {
		if record.partitionedCRLs != nil {
			// Checked by the partitioned CRL logic in Probe.
			continue
		}
		cert := byFingerprint[record.fingerprint]
		if cert == nil {
			errs = append(errs, fmt.Errorf("no PEM found in CCADB for %q (%s)", record.name, record.fingerprint))
			continue
		}
		// The requirement only covers unexpired and unrevoked CA certificates.
		if now.After(cert.NotAfter) || (record.revocationStatus != "" && record.revocationStatus != "Not Revoked") {
			continue
		}

		want := wantBySKID[record.skid]
		got := make(map[string]struct{}, len(record.fullCRLs))
		for _, url := range record.fullCRLs {
			got[url] = struct{}{}
		}

		var missing, extra []string
		for url := range want {
			if _, ok := got[url]; !ok {
				missing = append(missing, url)
			}
		}
		for url := range got {
			if _, ok := want[url]; !ok {
				extra = append(extra, url)
			}
		}
		slices.Sort(missing)
		slices.Sort(extra)
		if len(missing) > 0 {
			errs = append(errs, fmt.Errorf("%q (%s): CRLDPs %q appear in unexpired certificates it issued, but are not disclosed in CCADB",
				record.name, record.fingerprint, missing))
		}
		if len(extra) > 0 {
			errs = append(errs, fmt.Errorf("%q (%s): CRLs %q are disclosed in CCADB, but do not appear in any unexpired certificate it issued",
				record.name, record.fingerprint, extra))
		}

		for _, url := range record.fullCRLs {
			d := disclosure{record.skid, url}
			if !seen[d] {
				seen[d] = true
				toFetch = append(toFetch, d)
			}
		}
	}

	for _, d := range toFetch {
		// Because this prober fetches URLs controlled by external input (CCADB),
		// we rely on this regexp avoid arbitrary content fetching (SSRF).
		if !c.caCRLRegexp.MatchString(d.url) {
			errs = append(errs, fmt.Errorf("CA CRL %s does not match regexp %s", d.url, c.caCRLRegexp))
			continue
		}
		err := checkCACRL(ctx, d.url, bySKID[d.skid], c.caCRLAgeLimit)
		if err != nil {
			errs = append(errs, fmt.Errorf("fetching %s: %w", d.url, err))
		}
	}

	return errs
}

func checkCACRL(ctx context.Context, url string, issuer *x509.Certificate, ageLimit time.Duration) error {
	if issuer == nil {
		return errors.New("no issuer certificate found")
	}

	body, err := httpGet(ctx, url)
	if err != nil {
		return err
	}

	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		return err
	}

	// Our root CRLs have an issuingDistributionPoint that only sets
	// onlyContainsCACerts, with no distributionPoint. But if it does name URIs,
	// one must match the URL the CRL was fetched from.
	idps, err := idp.GetIDPURIs(crl.Extensions)
	if err != nil {
		return fmt.Errorf("extracting IssuingDistributionPoint URIs: %w", err)
	}
	if len(idps) > 0 && !slices.Contains(idps, url) {
		return fmt.Errorf("CRL had mismatched IDP %s", idps)
	}

	if time.Now().After(crl.NextUpdate) {
		return fmt.Errorf("nextUpdate is in the past: %v", crl.NextUpdate)
	}

	return checker.ValidateCACRL(crl, issuer, ageLimit)
}

// init is called at runtime and registers this prober type.
func init() {
	probers.Register(CCADBConf{})
}
