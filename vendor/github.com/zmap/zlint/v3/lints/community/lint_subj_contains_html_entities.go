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

package community

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"fmt"
	"reflect"
	"regexp"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_subj_contains_html_entities",
			Description:   "Detects the presence of HTML entities (e.g. '&amp;') in the Subject, which probably shouldn't be there",
			Source:        lint.Community,
			EffectiveDate: util.ZeroDate,
		},
		Lint: NewSubjectContainsHTMLEntities,
	})
}

type subjectContainsHTMLEntities struct {
	Skip bool `comment:"Set this to true to skip this lint"`
}

func NewSubjectContainsHTMLEntities() lint.LintInterface {
	return &subjectContainsHTMLEntities{
		Skip: false,
	}
}

func (l *subjectContainsHTMLEntities) Configure() interface{} {
	return l
}

func (l *subjectContainsHTMLEntities) CheckApplies(c *x509.Certificate) bool {
	return true
}

var htmlEntitiesRegExp = regexp.MustCompile("&#?[a-zA-Z0-9]+;")

func containsHTMLEntities(s string) bool {
	return htmlEntitiesRegExp.MatchString(s)
}

func (l *subjectContainsHTMLEntities) Execute(c *x509.Certificate) *lint.LintResult {

	if l.Skip {
		return &lint.LintResult{Status: lint.Pass}
	}

	targetFields := []string{
		"GivenName",
		"Surname",
		"CommonNames",
		"OrganizationalUnit",
		"Organization",
		"Locality",
		"Province",
		"StreetAddress",
		"PostalCode",
		"OrganizationIDs",
		"JurisdictionLocality",
		"JurisdictionProvince",
	}

	value := reflect.ValueOf(c.Subject)

	for _, fieldName := range targetFields {
		field := value.FieldByName(fieldName)
		strSlice := field.Interface().([]string)

		if len(strSlice) > 0 {
			if containsHTMLEntities(strSlice[0]) {
				return &lint.LintResult{
					Status:  lint.Error,
					Details: fmt.Sprintf("Subject.%s contains an HTML entity", fieldName),
				}
			}
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
