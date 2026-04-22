package notmain

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/blog"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/crl/checker"
)

func downloadShard(url string) (*x509.RevocationList, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("downloading crl: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downloading crl: http status %d", resp.StatusCode)
	}

	crlBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading CRL bytes: %w", err)
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CRL: %w", err)
	}

	return crl, nil
}

func main() {
	urlFile := flag.String("crls", "", "path to a file containing a JSON Array of CRL URLs")
	issuerFile := flag.String("issuer", "", "path to an issuer certificate on disk, required, '-' to disable validation")
	ageLimitStr := flag.String("ageLimit", "168h", "maximum allowable age of a CRL shard")
	emitRevoked := flag.Bool("emitRevoked", false, "emit revoked serial numbers on stdout, one per line, hex-encoded")
	save := flag.Bool("save", false, "save CRLs to files named after the URL")
	flag.Parse()

	logger := cmd.NewLogger(blog.Config{StdoutLevel: 6, SyslogLevel: -1})
	cmd.LogStartup(logger)
	ctx := context.Background()

	urlFileContents, err := os.ReadFile(*urlFile)
	cmd.FailOnError(err, "Reading CRL URLs file")

	var urls []string
	err = json.Unmarshal(urlFileContents, &urls)
	cmd.FailOnError(err, "Parsing JSON Array of CRL URLs")

	if *issuerFile == "" {
		cmd.Fail("-issuer is required, but may be '-' to disable validation")
	}

	var issuer *x509.Certificate
	if *issuerFile != "-" {
		issuer, err = core.LoadCert(*issuerFile)
		cmd.FailOnError(err, "Loading issuer certificate")
	} else {
		logger.Warn(ctx, "CRL signature validation disabled")
	}

	ageLimit, err := time.ParseDuration(*ageLimitStr)
	cmd.FailOnError(err, "Parsing age limit")

	errCount := 0
	seenSerials := make(map[string]struct{})
	totalBytes := 0
	oldestTimestamp := time.Time{}
	for _, u := range urls {
		ctx := blog.ContextWith(ctx, slog.String("url", u))
		crl, err := downloadShard(u)
		if err != nil {
			errCount += 1
			logger.Error(ctx, "fetching CRL failed", err)
			continue
		}

		if *save {
			parsedURL, err := url.Parse(u)
			if err != nil {
				logger.Error(ctx, "parsing url", err)
				continue
			}
			filename := fmt.Sprintf("%s%s", parsedURL.Host, strings.ReplaceAll(parsedURL.Path, "/", "_"))
			err = os.WriteFile(filename, crl.Raw, 0660)
			if err != nil {
				logger.Error(ctx, "writing file", err)
				continue
			}
		}

		totalBytes += len(crl.Raw)

		zcrl, err := x509.ParseRevocationList(crl.Raw)
		if err != nil {
			errCount += 1
			logger.Error(ctx, "parsing CRL failed", err)
			continue
		}

		err = checker.Validate(zcrl, issuer, ageLimit)
		if err != nil {
			errCount += 1
			logger.Error(ctx, "checking CRL failed", err)
			continue
		}

		if oldestTimestamp.IsZero() || crl.ThisUpdate.Before(oldestTimestamp) {
			oldestTimestamp = crl.ThisUpdate
		}

		for _, c := range crl.RevokedCertificateEntries {
			serial := core.SerialToString(c.SerialNumber)
			if _, seen := seenSerials[serial]; seen {
				errCount += 1
				logger.Error(ctx, "serial seen in multiple shards", errors.New("duplicate serial"), blog.Serial(serial))
				continue
			}
			seenSerials[serial] = struct{}{}
		}
	}

	if *emitRevoked {
		for serial := range seenSerials {
			fmt.Println(serial)
		}
	}

	if errCount != 0 {
		cmd.Fail(fmt.Sprintf("Encountered %d errors", errCount))
	}

	logger.AuditInfo(ctx, "CRL checking complete",
		slog.Int("numCRLs", len(urls)),
		slog.Int("numSerials", len(seenSerials)),
		slog.Int("numBytes", totalBytes),
		slog.Time("oldestCRL", oldestTimestamp),
	)
}

func init() {
	cmd.RegisterCommand("crl-checker", main, nil)
}
