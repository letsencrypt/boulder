package ccadb

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/letsencrypt/boulder/observer/probers"
	"github.com/letsencrypt/boulder/strictyaml"
	"github.com/prometheus/client_golang/prometheus"
	"io"
	"maps"
	"regexp"
	"slices"
	"time"

	"github.com/letsencrypt/boulder/crl/checker"
	"github.com/letsencrypt/boulder/crl/idp"
)

// CCADBConf is exported to receive YAML configuration.
type CCADBConf struct {
	AllCertificatesCSVURL string `yaml:"allCertificatesCSVURL"`
	CertificatePEMsURL    string `yaml:"certificatePEMsURL"`
	CAOwner               string `yaml:"caOwner"`
	CRLAgeLimit           string `yaml:"crlAgeLimit"`
	// Because this prober fetches URLs controlled by external input (CCADB), we
	// check this regexp to avoid arbitrary content fetching (SSRF).
	CRLRegexp string `yaml:"crlRegexp"`
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
	ccadbAllCertificatesCSVURL := "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv4"
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

	crlRegexp := `^http://[a-z0-9-]+\.c\.lencr\.org/\d+\.crl$`
	if c.CRLRegexp != "" {
		crlRegexp = c.CRLRegexp
	}

	re, err := regexp.Compile(crlRegexp)
	if err != nil {
		return nil, fmt.Errorf("parsing CRL regexp %q: %s", crlRegexp, err)
	}

	return &CCADBProber{
		allCertificatesCSVURL: ccadbAllCertificatesCSVURL,
		certificatePEMsURL:    certificatePEMsURL,
		caOwner:               caOwner,
		crlAgeLimit:           ageLimitDuration,
		crlRegexp:             re,
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

// CCADBProber fetches the AllCertificatesRecordsReport from CCADB, filters for a
// specific CA Owner (defaults to 'Internet Security Research Group'), and
// fetches all CRLs found.
//
// It checks that the CRLs:
//   - Are not too old
//   - Have an issuingDistributionPoint that matches the URL from which they
//     were fetched
//   - Have a valid signature based on their issuer SKID from CCADB
//   - Don't have duplicate serial numbers across different CRLs
type CCADBProber struct {
	allCertificatesCSVURL string
	certificatePEMsURL    string
	caOwner               string
	crlAgeLimit           time.Duration
	crlRegexp             *regexp.Regexp
}

func (c CCADBProber) Kind() string {
	return "CCADB"
}

func (c CCADBProber) Name() string {
	return "CCADB"
}

func (c *CCADBProber) Probe(ctx context.Context) error {
	issuers, err := c.getAllIntermediates(ctx)
	if err != nil {
		return err
	}

	crlURLs, err := c.getCRLURLs(ctx, issuers)
	if err != nil {
		return err
	}

	serials := make(map[string]*x509.RevocationList)

	var errs []error
	for skid, urls := range crlURLs {
		issuer := issuers[skid]
		if issuer == nil {
			errs = append(errs, fmt.Errorf("no issuer found for skid %x", skid))
			continue
		}

		for _, url := range urls {
			// This can happen when an issuer is not yet issuing.
			if url == "" {
				continue
			}

			if !c.crlRegexp.MatchString(url) {
				errs = append(errs, fmt.Errorf("CRL %s does not match regexp %s", url, c.crlRegexp))
				continue
			}

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
				if otherCRL, ok := serials[serialByteString]; ok {
					otherCRLURL, err := getIDP(otherCRL)
					if err != nil {
						errs = append(errs, fmt.Errorf("failed to get CRL from other CRL: %s", err))
						continue
					}
					errs = append(errs, fmt.Errorf("serial %x seen on multiple CRLs: %s and %s", entry.SerialNumber, otherCRLURL, url))
				}
				serials[serialByteString] = crl
			}
		}
	}

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

func (c CCADBProber) getAllIntermediates(ctx context.Context) (map[string]*x509.Certificate, error) {
	certs, err := c.getDecadeIntermediates(ctx, 2010)
	if err != nil {
		return nil, err
	}

	moreCerts, err := c.getDecadeIntermediates(ctx, 2020)
	if err != nil {
		return nil, err
	}

	maps.Copy(certs, moreCerts)
	return certs, nil
}

func (c CCADBProber) getDecadeIntermediates(ctx context.Context, decade int) (map[string]*x509.Certificate, error) {
	url := fmt.Sprintf("%s?NotBeforeDecade=%d", c.certificatePEMsURL, decade)
	header, reader, err := getCSV(ctx, url)
	if err != nil {
		return nil, err
	}

	pemIndex := slices.Index(header, "X.509 Certificate (PEM)")
	if pemIndex == -1 {
		return nil, fmt.Errorf("no column named \"X.509 Certificate (PEM)\" in %s", url)
	}

	ret := make(map[string]*x509.Certificate)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%q: %w", url, err)
		}

		if len(record) < pemIndex {
			continue
		}

		block, _ := pem.Decode([]byte(record[pemIndex]))
		if block == nil {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		ret[string(cert.SubjectKeyId)] = cert
	}

	if len(ret) == 0 {
		return nil, fmt.Errorf("no valid certificate PEMs found in %s", url)
	}
	return ret, nil
}

// returns a map from issuer SKID to list of URLs
func (c CCADBProber) getCRLURLs(ctx context.Context, issuers map[string]*x509.Certificate) (map[string][]string, error) {
	header, reader, err := getCSV(ctx, c.allCertificatesCSVURL)
	if err != nil {
		return nil, err
	}

	const (
		owner           = "CA Owner"
		crl             = "JSON Array of Partitioned CRLs"
		skid            = "Subject Key Identifier"
		certificateName = "Certificate Name"
	)

	columns := map[string]int{}
	for _, headerName := range []string{owner, crl, skid, certificateName} {
		index := slices.Index(header, headerName)
		if index == -1 {
			return nil, fmt.Errorf("no column named %q in %s", headerName, c.allCertificatesCSVURL)
		}
		columns[headerName] = index
	}

	allCRLs := make(map[string][]string)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%q: %w", c.allCertificatesCSVURL, err)
		}
		if record[columns[owner]] != c.caOwner {
			continue
		}
		crlJSON := record[columns[crl]]
		if crlJSON == "" {
			continue
		}
		var crls []string
		err = json.Unmarshal([]byte(crlJSON), &crls)
		if err != nil {
			return nil, err
		}
		certificateName := record[columns[certificateName]]
		skidBase64 := record[columns[skid]]
		skid, err := base64.StdEncoding.DecodeString(skidBase64)
		if err != nil {
			return nil, err
		}
		if len(skid) == 0 {
			return nil, fmt.Errorf("no skid for %q", certificateName)
		}
		stringSKID := string(skid)
		if issuers[stringSKID] == nil {
			return nil, fmt.Errorf("CCADB contained %q with SKID %x, but that SKID is not in issuers CRL at %s?decade=XXXX",
				certificateName, skid, c.certificatePEMsURL)
		}
		// An issuer can show up multiple times, under different cross-signs. However,
		// it must have the same list of CRLs each time.
		if c := allCRLs[stringSKID]; c != nil && !slices.Equal(c, crls) {
			return nil, fmt.Errorf("CCADB contained %q with SKID %x multiple times with different CRLs", certificateName, skid)
		}
		allCRLs[stringSKID] = crls
	}

	if len(allCRLs) == 0 {
		return nil, fmt.Errorf("no records found in CCADB for CA Owner %q", c.caOwner)
	}
	return allCRLs, nil
}

// init is called at runtime and registers this prober type.
func init() {
	probers.Register(CCADBConf{})
}
