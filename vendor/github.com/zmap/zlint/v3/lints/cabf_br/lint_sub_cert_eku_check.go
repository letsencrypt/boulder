package cabf_br

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

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type subExtKeyUsageCheck struct{}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_sub_cert_eku_check",
			Description:   "Subscriber certificates MUST have id-kp-serverAuth and MAY have id-kp-clientAuth present in extKeyUsage",
			Citation:      "BRs: 7.1.2.7.10 Subscriber Certificate Extended Key Usage",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABFBRs_2_0_0_Date,
		},
		Lint: NewSubExtKeyUsageCheck,
	})
}

func NewSubExtKeyUsageCheck() lint.LintInterface {
	return &subExtKeyUsageCheck{}
}

func (l *subExtKeyUsageCheck) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && util.IsExtInCert(c, util.EkuSynOid)
}

func (l *subExtKeyUsageCheck) Execute(c *x509.Certificate) *lint.LintResult {
	var hasClientAuthEKU, hasServerAuthEKU bool

	for _, eku := range c.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			hasServerAuthEKU = true

		case x509.ExtKeyUsageClientAuth:
			hasClientAuthEKU = true

		case x509.ExtKeyUsageAny, x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageTimeStamping,
			x509.ExtKeyUsageOcspSigning, x509.ExtKeyUsageEmailProtection:

			return &lint.LintResult{Status: lint.Error, Details: util.GetEKUString(eku) + " MUST NOT be present"}
		}
	}

	if !hasServerAuthEKU {
		return &lint.LintResult{Status: lint.Error, Details: "id-kp-serverAuth MUST be present"}
	}

	for _, eku := range c.UnknownExtKeyUsage {
		if eku.Equal(util.PreCertificateSigningCertificateEKU) {
			return &lint.LintResult{Status: lint.Error, Details: "Precertificate Signing Certificate extKeyUsage MUST NOT be present"}
		}
	}

	if (len(c.ExtKeyUsage) > 2 && !hasClientAuthEKU) || len(c.UnknownExtKeyUsage) > 0 {
		return &lint.LintResult{Status: lint.Warn, Details: "any other value than id-kp-serverAuth and id-kp-clientAuth is NOT RECOMMENDED"}
	}

	return &lint.LintResult{Status: lint.Pass}
}
