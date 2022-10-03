package notmain

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/crl/crl_x509"
	"github.com/letsencrypt/boulder/issuance"
	"github.com/letsencrypt/boulder/linter"
	crlint "github.com/letsencrypt/boulder/linter/lints/crl"
)

func downloadShard(url string) (*crl_x509.RevocationList, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("downloading crl: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downloading crl: http status %d", resp.StatusCode)
	}

	crlBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading CRL bytes: %w", err)
	}

	crl, err := crl_x509.ParseRevocationList(crlBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CRL: %w", err)
	}

	return crl, nil
}

func validateShard(crl *crl_x509.RevocationList, issuer *issuance.Certificate, ageLimit time.Duration) error {
	err := linter.ProcessResultSet(crlint.LintCRL(crl))
	if err != nil {
		return fmt.Errorf("linting CRL: %w", err)
	}

	err = crl.CheckSignatureFrom(issuer.Certificate)
	if err != nil {
		return fmt.Errorf("checking CRL signature: %w", err)
	}

	if time.Since(crl.ThisUpdate) >= ageLimit {
		return fmt.Errorf("thisUpdate more than %s in the past: %v", ageLimit, crl.ThisUpdate)
	}

	return nil
}

func main() {
	urlFile := flag.String("crls", "", "path to a file containing a JSON Array of CRL URLs")
	issuerFile := flag.String("issuer", "", "path to an issuer certificate on disk")
	ageLimitStr := flag.String("ageLimit", "168h", "maximum allowable age of a CRL shard")
	emitRevoked := flag.Bool("emitRevoked", false, "emit revoked serial numbers on stdout, one per line, hex-encoded")
	flag.Parse()

	logger := cmd.NewLogger(cmd.SyslogConfig{StdoutLevel: 6, SyslogLevel: -1})

	urlFileContents, err := os.ReadFile(*urlFile)
	cmd.FailOnError(err, "Reading CRL URLs file")

	var urls []string
	err = json.Unmarshal(urlFileContents, &urls)
	cmd.FailOnError(err, "Parsing JSON Array of CRL URLs")

	issuer, err := issuance.LoadCertificate(*issuerFile)
	cmd.FailOnError(err, "Loading issuer certificate")

	ageLimit, err := time.ParseDuration(*ageLimitStr)
	cmd.FailOnError(err, "Parsing age limit")

	errCount := 0
	for _, url := range urls {
		crl, err := downloadShard(url)
		if err != nil {
			errCount += 1
			logger.Errf("fetching CRL %q failed: %s", url, err)
			continue
		}

		err = validateShard(crl, issuer, ageLimit)
		if err != nil {
			errCount += 1
			logger.Errf("checking CRL %q failed: %s", url, err)
			continue
		}

		if *emitRevoked {
			for _, c := range crl.RevokedCertificates {
				fmt.Printf("%x\n", c.SerialNumber)
			}
		}
	}

	if errCount != 0 {
		cmd.Fail(fmt.Sprintf("Encountered %d errors", errCount))
	}
	logger.AuditInfo("All CRLs validated")
}

func init() {
	cmd.RegisterCommand("crl-checker", main)
}
