package rfc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type certViaPKIMetal struct {
	Addr        string        `toml:"addr" comment:"The address where a pkilint REST API can be reached."`
	Severity    string        `toml:"severity" comment:"The minimum severity of findings to report (meta, debug, info, notice, warning, error, bug, or fatal)."`
	Timeout     time.Duration `toml:"timeout" comment:"How long, in nanoseconds, to wait before giving up."`
	IgnoreLints []string      `toml:"ignore_lints" comment:"The unique Validator:Code IDs of lint findings which should be ignored."`
}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_pkimetal_lint_cabf_serverauth_cert",
			Description:   "Runs pkimetal's suite of cabf serverauth certificate lints",
			Citation:      "https://github.com/pkimetal/pkimetal",
			Source:        lint.Community,
			EffectiveDate: util.CABEffectiveDate,
		},
		Lint: NewCertViaPKIMetal,
	})
}

func NewCertViaPKIMetal() lint.CertificateLintInterface {
	return &certViaPKIMetal{}
}

func (l *certViaPKIMetal) Configure() any {
	return l
}

func (l *certViaPKIMetal) CheckApplies(c *x509.Certificate) bool {
	// This lint applies to all certificates issued by Boulder, as long as it has
	// been configured with an address to reach out to. If not, skip it.
	return l.Addr != ""
}

// finding matches the repeated portion of PKIMetal's documented JSON response.
// https://github.com/pkimetal/pkimetal/blob/578ac224a7ca3775af51b47fce16c95753d9ac8d/doc/openapi.yaml#L201-L221
type finding struct {
	Linter   string `json:"linter"`
	Finding  string `json:"finding"`
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Field    string `json:"field"`
}

func (l *certViaPKIMetal) Execute(c *x509.Certificate) *lint.LintResult {
	timeout := l.Timeout
	if timeout == 0 {
		timeout = 100 * time.Millisecond
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// reqForm matches PKIMetal's documented form-urlencoded request format. It
	// does not include the "format" or "profile" fields, as their default values
	// ("json" and "autodetect", respectively) are good for our purposes.
	// https://github.com/pkimetal/pkimetal/blob/578ac224a7ca3775af51b47fce16c95753d9ac8d/doc/openapi.yaml#L179-L194
	reqForm := url.Values{}
	reqForm.Set("b64input", base64.StdEncoding.EncodeToString(c.Raw))
	reqForm.Set("severity", l.Severity)

	url := fmt.Sprintf("%s/lintcert", l.Addr)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(reqForm.Encode()))
	if err != nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("creating pkimetal request: %s", err),
		}
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("making POST request to pkimetal API: %s (timeout %s)", err, timeout),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("got status %d (%s) from pkimetal API", resp.StatusCode, resp.Status),
		}
	}

	resJSON, err := io.ReadAll(resp.Body)
	if err != nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("reading response from pkimetal API: %s", err),
		}
	}

	var res []finding
	err = json.Unmarshal(resJSON, &res)
	if err != nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("parsing response from pkimetal API: %s", err),
		}
	}

	var findings []string
	for _, finding := range res {
		id := fmt.Sprintf("%s:%s", finding.Linter, finding.Code)
		if slices.Contains(l.IgnoreLints, id) {
			continue
		}
		desc := fmt.Sprintf("%s from %s at %s", finding.Severity, id, finding.Field)
		if finding.Finding != "" {
			desc = fmt.Sprintf("%s: %s", desc, finding.Finding)
		}
		findings = append(findings, desc)
	}

	if len(findings) != 0 {
		// Group the findings by severity, for human readers.
		slices.Sort(findings)
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("got %d lint findings from pkimetal API: %s", len(findings), strings.Join(findings, "; ")),
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
