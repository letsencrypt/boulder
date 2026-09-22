package rfc

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"github.com/letsencrypt/boulder/linter/pkimetal"
)

type certViaPKIMetal struct {
	pkimetal.Client
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
	return &l.Config
}

func (l *certViaPKIMetal) CheckApplies(c *x509.Certificate) bool {
	// This lint applies to all certificates issued by Boulder, as long as it has
	// been configured with a socket to reach out to. If not, skip it.
	return l.Enabled()
}

func (l *certViaPKIMetal) Execute(c *x509.Certificate) *lint.LintResult {
	res, err := l.Client.Execute("lintcert", c.Raw)
	if err != nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: err.Error(),
		}
	}

	return res
}
