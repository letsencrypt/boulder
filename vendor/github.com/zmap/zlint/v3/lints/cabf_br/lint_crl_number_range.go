/*
 * ZLint Copyright 2024 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package cabf_br

import (
	"fmt"
	"math/big"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
)

/*
 * Baseline Requirements: 7.2.2 CRL and CRL entry extensions
 * CRLNumber MUST be an INTEGER greater than or equal
 * to zero (0) and less than 2^159 and convey a strictly
 * increasing sequence.
 */

func init() {
	lint.RegisterRevocationListLint(&lint.RevocationListLint{
		LintMetadata: lint.LintMetadata{
			Name:        "e_crl_number_out_of_range",
			Description: "The CRL number must be greater than or equal to 0 and less than 2^159.",
			Citation:    "BRs: 7.2.2",
			Source:      lint.CABFBaselineRequirements,
		},
		Lint: func() lint.RevocationListLintInterface { return &crlNumberLimit{} },
	})
}

type crlNumberLimit struct{}

func (*crlNumberLimit) CheckApplies(c *x509.RevocationList) bool {
	return true
}

// Execute checks that the CRL number is within the valid range [0, 2^159).
func (*crlNumberLimit) Execute(c *x509.RevocationList) *lint.LintResult {
	if c.Number == nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRL number extension is missing",
		}
	}
	if c.Number.Cmp(big.NewInt(0)) < 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("CRL number is negative: %v", c.Number),
		}
	}
	crlNumberUpperBound := new(big.Int).Exp(big.NewInt(2), big.NewInt(159), nil)
	if c.Number.Cmp(crlNumberUpperBound) >= 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("CRL number is greater than or equal to 2^159: %v", c.Number),
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
