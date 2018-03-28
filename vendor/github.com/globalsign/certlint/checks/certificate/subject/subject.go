package subject

import (
	"crypto/x509/pkix"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"
)

const checkName = "Subject Check"

func init() {
	filter := &checks.Filter{
		//Type: []string{"DV", "OV", "IV", "EV"},
	}
	checks.RegisterCertificateCheck(checkName, filter, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
func Check(d *certdata.Data) *errors.Errors {
	return checkDN(d.Type, d.Cert.Subject.Names)
}

// Subject Distinguished Name Fields
func checkDN(vetting string, dn []pkix.AttributeTypeAndValue) *errors.Errors {
	var e = errors.New(nil)

	// DNS must not be empty
	if len(dn) == 0 {
		e.Err("Distinguished Name contains no values")
		return e
	}

	// OV & EV requirements
	if vetting == "OV" || vetting == "EV" {
		if !inDN(dn, organizationName) {
			e.Err("organizationName is required for %s certificates", vetting)
		}
	}

	// EV specific requirements
	if vetting == "EV" {
		if !inDN(dn, localityName) {
			e.Err("localityName is required for %s certificates", vetting)
		}
		if !inDN(dn, businessCategory) {
			e.Err("businessCategory is required for %s certificates", vetting)
		}
		if !inDN(dn, jurisdictionCountryName) {
			e.Err("jurisdictionCountryName is required for %s certificates", vetting)
		}
		if !inDN(dn, serialNumber) {
			e.Err("serialNumber is required for %s certificates", vetting)
		}
	}

	// Field related requirements
	//
	// Max field length:
	// https://www.itu.int/ITU-T/formal-language/itu-t/x/x520/2001/UpperBounds.html
	for _, n := range dn {
		switch {

		// commonName
		// If present, this field MUST contain a single IP address or Fully‐Qualified Domain Name
		case commonName.Equal(n.Type):
			// report deprecated common name field as info until not commenly used/accepted
			e.Info("commonName field is deprecated")

			// check if value is exceeding max length
			if err := commonName.Valid(n.Value); err != nil {
				e.Err("commonName %s", err.Error())
			}

		case emailAddress.Equal(n.Type):
			// report deprecated email address field as info until not commenly used/accepted
			e.Info("emailAddress field is deprecated")

			// RFC5280: ub-emailaddress-length was changed from 128 to 255 in order to
			// align with PKCS #9 [RFC2985].
			if err := emailAddress.Valid(n.Value); err != nil {
				e.Err("emailAddress %s", err.Error())
			}

		// surname
		// A Certificate containing a givenName field or surname field MUST contain
		// the (2.23.140.1.2.3) Certificate Policy OID.
		case surname.Equal(n.Type):
			// Prohibited
			if !inDN(dn, givenName) {
				e.Err("surname may only set in combination with givenName")
			}
			// Require field if surname is set
			if !inDN(dn, localityName) && !inDN(dn, stateOrProvinceName) {
				e.Err("localityName or stateOrProvinceName is required if surname is set")
			}

			// ub-surname-length INTEGER ::= 40
			if err := surname.Valid(n.Value); err != nil {
				e.Err("surname %s", err.Error())
			}

		// countryName
		case countryName.Equal(n.Type):
			// TODO: Check against the values in ISO 3166‐1
			if len(n.Value.(string)) != 2 {
				e.Err("countryName MUST contain the two-letter ISO 3166-1 country code")
			}

			// jurisdictionCountryName
		case jurisdictionCountryName.Equal(n.Type):
			// TODO: Check against the values in ISO 3166‐1
			if len(n.Value.(string)) != 2 {
				e.Err("jurisdictionCountryName MUST contain the two-letter ISO 3166-1 country code")
			}

		// localityName
		case localityName.Equal(n.Type):
			// Prohibited
			if !inDN(dn, organizationName) && !(inDN(dn, givenName) && inDN(dn, surname)) {
				e.Err("localityName is not allowed without organizationName or givenName and surname")
			}

			if err := localityName.Valid(n.Value); err != nil {
				e.Err("localityName %s", err.Error())
			}

		// stateOrProvinceName
		case stateOrProvinceName.Equal(n.Type):
			// Prohibited
			if !inDN(dn, organizationName) && !(inDN(dn, givenName) && inDN(dn, surname)) {
				e.Err("stateOrProvinceName is not allowed without organizationName or givenName and surname")
			}

			if err := stateOrProvinceName.Valid(n.Value); err != nil {
				e.Err("stateOrProvinceName %s", err.Error())
			}

		// streetAddress
		case streetAddress.Equal(n.Type):
			// Prohibited
			if !inDN(dn, organizationName) && !(inDN(dn, givenName) && inDN(dn, surname)) {
				e.Err("streetAddress is not allowed without organizationName or givenName and surname")
			}

			if err := streetAddress.Valid(n.Value); err != nil {
				e.Err("streetAddress %s", err.Error())
			}

		// postalCode
		case postalCode.Equal(n.Type):
			// Prohibited
			if !inDN(dn, organizationName) && !(inDN(dn, givenName) && inDN(dn, surname)) {
				e.Err("postalCode is not allowed without organizationName or givenName and surname")
			}

			if err := postalCode.Valid(n.Value); err != nil {
				e.Err("postalCode %s", err.Error())
			}

		// organizationName
		case organizationName.Equal(n.Type):
			// Require field if organizationName is set
			if !inDN(dn, localityName) && !inDN(dn, stateOrProvinceName) {
				e.Err("localityName or stateOrProvinceName is required if organizationName is set")
			}
			if !inDN(dn, stateOrProvinceName) {
				e.Err("stateOrProvinceName is required if organizationName is set")
			}
			if !inDN(dn, countryName) {
				e.Err("countryName is required if organizationName is set")
			}

			if err := organizationName.Valid(n.Value); err != nil {
				e.Err("organizationName %s", err.Error())
			}

		// organizationalUnitName
		case organizationalUnitName.Equal(n.Type):
			if err := organizationalUnitName.Valid(n.Value); err != nil {
				e.Err("organizationalUnitName %s", err.Error())
			}

		// businessCategory
		case businessCategory.Equal(n.Type):
			bc := n.Value.(string)
			if bc != "Private Organization" && bc != "Government Entity" && bc != "Business Entity" && bc != "Non-Commercial Entity" {
				e.Err("businessCategory should contain 'Private Organization', 'Government Entity', 'Business Entity', or 'Non-Commercial Entity'")
			}

			if err := businessCategory.Valid(n.Value); err != nil {
				e.Err("businessCategory %s", err.Error())
			}

		// serialNumber
		case serialNumber.Equal(n.Type):
			if err := serialNumber.Valid(n.Value); err != nil {
				e.Err("serialNumber %s", err.Error())
			}

		// givenName
		case givenName.Equal(n.Type):
			// Prohibited
			if !inDN(dn, surname) {
				e.Err("givenName may only set in combination with surname")
			}

			if err := givenName.Valid(n.Value); err != nil {
				e.Err("givenName %s", err.Error())
			}
		}
	}

	return e
}

func inDN(dn []pkix.AttributeTypeAndValue, attr object) bool {
	for _, n := range dn {
		if attr.Equal(n.Type) {
			return true
		}
	}
	return false
}
