package subjectaltname

import (
	goerr "errors"
	"strings"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"

	"golang.org/x/net/idna"
)

const checkName = "Subject Alternative Names Check"

var idnaProfile *idna.Profile
var idnaUnderscoreError = goerr.New("idna: disallowed rune U+005F")

func init() {
	idnaProfile = idna.New(
		idna.BidiRule(),
		idna.MapForLookup(),
		idna.ValidateForRegistration(),
		idna.ValidateLabels(true),
		idna.VerifyDNSLength(true),
		idna.StrictDomainName(true),
		idna.Transitional(false))

	checks.RegisterCertificateCheck(checkName, nil, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
func Check(d *certdata.Data) *errors.Errors {
	var e = errors.New(nil)

	// TODO: Should we check against cross usage of certificate types (for example DV certificate with emial address)?

	switch d.Type {
	case "PS":
		// TODO: Check EmailAddresses in the Subject DN
		if len(d.Cert.EmailAddresses) == 0 {
			e.Err("Certificate doesn't contain any subjectAltName")
			return e
		}
		for _, s := range d.Cert.EmailAddresses {
			// Splitting domain of mail address, using lowercase
			em := strings.SplitAfter(strings.ToLower(s), "@")
			if len(em) != 2 {
				e.Err("Certificate subjectAltName '%s' contains an invalid email address", s)
				continue
			}

			// Check email address domain part
			if _, err := idnaProfile.ToASCII(em[1]); err != nil {
				e.Err("Certificate subjectAltName '%s', %s", s, err.Error())
			}

			// TODO: Implement more checks for the left side of the @ sign
			if strings.Contains(em[0], " ") {
				e.Err("Certificate subjectAltName '%s' contains a whitespace", s)
			}
		}

	case "DV", "OV", "EV":
		if len(d.Cert.DNSNames) == 0 && len(d.Cert.IPAddresses) == 0 {
			e.Err("Certificate doesn't contain any subjectAltName")
			return e
		}

		// While the commonname is not a subjectAltName we use the same rule to
		// validate the domain name. Check with stripped wildcards as they are non
		// registrable.
		if _, err := idnaProfile.ToASCII(strings.TrimPrefix(strings.ToLower(d.Cert.Subject.CommonName), "*.")); err != nil && err != idnaUnderscoreError {
			e.Err("Certificate CommonName '%s', %s", d.Cert.Subject.CommonName, err.Error())
		}

		var cnInSan bool
		for _, s := range d.Cert.DNSNames {
			if strings.EqualFold(d.Cert.Subject.CommonName, s) {
				cnInSan = true
			}

			// Check subjectAltName with stripped wildcards as they are non registrable
			if _, err := idnaProfile.ToASCII(strings.TrimPrefix(strings.ToLower(s), "*.")); err != nil && err != idnaUnderscoreError {
				e.Err("Certificate subjectAltName '%s', %s", s, err.Error())
			}
		}

		// Maybe it's an IP address
		if !cnInSan {
			for _, s := range d.Cert.IPAddresses {
				if strings.EqualFold(d.Cert.Subject.CommonName, s.String()) {
					cnInSan = true
				}
			}
		}

		if !cnInSan {
			e.Err("Certificate CN is not listed in subjectAltName")
		}
	}

	return e
}
