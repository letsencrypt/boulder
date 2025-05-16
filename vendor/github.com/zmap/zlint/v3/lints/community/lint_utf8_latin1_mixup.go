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
	"strings"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_utf8_latin1_mixup",
			Description:   "Checks for wrongly encoded diacritics due to UTF-8 mistaken for Latin-1",
			Citation:      "See https://en.wikipedia.org/wiki/ISO/IEC_8859-1",
			Source:        lint.Community,
			EffectiveDate: util.ZeroDate,
		},
		Lint: NewUTF8Latin1Mixup,
	})
}

type UTF8Latin1Mixup struct{}

func NewUTF8Latin1Mixup() lint.LintInterface {
	return &UTF8Latin1Mixup{}
}

func (l *UTF8Latin1Mixup) CheckApplies(c *x509.Certificate) bool {
	return true
}

// Checks if the supplied string contains any wrongly encoded diacritics
// due to mistaking their correct UTF-8 encoding for Latin-1 code points
func containsUtf8Latin1Mixup(s string) bool {

	// This table does not cover 100% of all possible miscodings, but it avoids false positives.
	// The correct diacritic that each entry relates to is shown in the entry's trailing comment.
	miscodedDiacritics := []string{

		"Ã€", // À
		"Ã‚", // Â
		"Ãƒ", // Ã
		"Ã„", // Ä
		"Ã…", // Å
		"Ã†", // Æ
		"Ã‡", // Ç
		"Ãˆ", // È
		"Ã‰", // É
		"ÃŠ", // Ê
		"Ã‹", // Ë
		"ÃŒ", // Ì
		"ÃŽ", // Î
		"Ã‘", // Ñ
		"Ã’", // Ò
		"Ã“", // Ó
		"Ã”", // Ô
		"Ã•", // Õ
		"Ã–", // Ö
		"Ã—", // ×
		"Ã˜", // Ø
		"Ã™", // Ù
		"Ãš", // Ú
		"Ã›", // Û
		"Ãœ", // Ü
		"Ãž", // Þ
		"ÃŸ", // ß
		"Ã¡", // á
		"Ã¢", // â
		"Ã£", // ã
		"Ã¤", // ä
		"Ã¥", // å
		"Ã¦", // æ
		"Ã§", // ç
		"Ã¨", // è
		"Ã©", // é
		"Ãª", // ê
		"Ã«", // ë
		"Ã¬", // ì
		"Ã®", // î
		"Ã¯", // ï
		"Ã°", // ð
		"Ã±", // ñ
		"Ã²", // ò
		"Ã³", // ó
		"Ã´", // ô
		"Ãµ", // õ
		"Ã¶", // ö
		"Ã·", // ÷
		"Ã¸", // ø
		"Ã¹", // ù
		"Ãº", // ú
		"Ã»", // û
		"Ã¼", // ü
		"Ã½", // ý
		"Ã¾", // þ
		"Ã¿", // ÿ
	}

	for _, mixup := range miscodedDiacritics {
		if strings.Contains(s, mixup) {
			return true
		}
	}
	return false
}

func (l *UTF8Latin1Mixup) Execute(c *x509.Certificate) *lint.LintResult {
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
			if containsUtf8Latin1Mixup(strSlice[0]) {
				return &lint.LintResult{
					Status: lint.Error,
					Details: fmt.Sprintf("Subject.%s contains wrongly encoded diacritics (UTF-8 mistaken for Latin-1)",
						fieldName),
				}
			}
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
