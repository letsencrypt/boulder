package notmain

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/crl/crl_x509"
	"github.com/letsencrypt/boulder/issuance"
	"github.com/letsencrypt/boulder/linter"
	crlint "github.com/letsencrypt/boulder/linter/lints/crl"
)

func validateShard(url string, issuer *issuance.Certificate) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("downloading crl: %w", err)
	}

	crlBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading CRL bytes: %w", err)
	}

	crl, err := crl_x509.ParseRevocationList(crlBytes)
	if err != nil {
		return fmt.Errorf("parsing CRL: %w", err)
	}

	err = linter.ProcessResultSet(crlint.LintCRL(crl))
	if err != nil {
		return fmt.Errorf("linting CRL: %w", err)
	}

	err = crl.CheckSignatureFrom(issuer.Certificate)
	if err != nil {
		return fmt.Errorf("checking CRL signature: %w", err)
	}

	return nil
}

func main() {
	urlFile := flag.String("crls", "", "path to a file containing a JSON Array of CRL URLs")
	issuerFile := flag.String("issuer", "", "path to an issuer certificate on disk")
	flag.Parse()

	logger := cmd.NewLogger(cmd.SyslogConfig{StdoutLevel: 6, SyslogLevel: -1})

	urlFileContents, err := os.ReadFile(*urlFile)
	cmd.FailOnError(err, "Reading CRL URLs file")

	var urls []string
	err = json.Unmarshal(urlFileContents, &urls)
	cmd.FailOnError(err, "Parsing JSON Array of CRL URLs")

	issuer, err := issuance.LoadCertificate(*issuerFile)
	cmd.FailOnError(err, "Loading issuer certificate")

	errCount := 0
	for _, url := range urls {
		err = validateShard(url, issuer)
		if err != nil {
			errCount += 1
			logger.Errf("CRL %q failed: %s\n", url, err)
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
