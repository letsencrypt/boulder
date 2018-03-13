package certdata

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"

	psl "golang.org/x/net/publicsuffix"
)

// setCertificateType set the base on how we check for other requirements of the
// certificate. It's important that we reliably identify the purpose to apply
// the right checks for that certificate type.
func (d *Data) setCertificateType() error {
	// We want to be able to detect 'false' CA certificates, classify as CA
	// certificate is basic contains and key usage certsign are set.
	if d.Cert.IsCA && d.Cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		d.Type = "CA"
		return nil
	}

	// The fallback type is used when a certificate could be any of a range
	// but further checks need to define the exact type. When these checks fail
	// the fallback type is used.
	var fallbackType string

	// Based on ExtKeyUsage
	for _, ku := range d.Cert.ExtKeyUsage {
		switch ku {
		case x509.ExtKeyUsageServerAuth:
			// Try to determine certificate type via policy oid
			d.Type = getType(d.Cert.PolicyIdentifiers)
			fallbackType = "DV"
		case x509.ExtKeyUsageClientAuth:
			fallbackType = "PS"
		case x509.ExtKeyUsageEmailProtection:
			d.Type = "PS"
		case x509.ExtKeyUsageCodeSigning:
			d.Type = "CS"
		case x509.ExtKeyUsageTimeStamping:
			d.Type = "TS"
		case x509.ExtKeyUsageOCSPSigning:
			d.Type = "OCSP"
		}
	}

	// If we have no kown key usage, try the policy list again
	if d.Type == "" {
		d.Type = getType(d.Cert.PolicyIdentifiers)
	}

	// When determined by Policy Identifier we can stop
	if d.Type != "" {
		return nil
	}

	// Based on UnknownExtKeyUsage
	for _, ku := range d.Cert.UnknownExtKeyUsage {
		switch {
		case ku.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 19}):
			// dsEmailReplication
			d.Type = "PS"
			return nil
		case ku.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 8, 2, 2}):
			// IPSEC Protection
			d.Type = "IPSEC"
			return nil
		}
	}

	// Check if the e-mailAddress is set in the DN
	for _, n := range d.Cert.Subject.Names {
		switch {
		case n.Type.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}): // e-mailAddress
			d.Type = "PS"
			return nil
		}
	}

	// An @ sing in the common name is often used in PS.
	if strings.Contains(d.Cert.Subject.CommonName, "@") {
		d.Type = "PS"
		return nil
	} else if strings.Contains(d.Cert.Subject.CommonName, " ") {
		d.Type = "PS"
		return nil
	}

	// If it's a fqdn, it's a EV, OV or DV
	if suffix, _ := psl.PublicSuffix(strings.ToLower(d.Cert.Subject.CommonName)); len(suffix) > 0 {
		if len(d.Cert.Subject.Organization) > 0 {
			if len(d.Cert.Subject.SerialNumber) > 0 {
				d.Type = "EV"
				return nil
			}

			d.Type = "OV"
			return nil
		}

		d.Type = "DV"
		return nil
	}

	if len(fallbackType) > 0 {
		d.Type = fallbackType
		return nil
	}

	if d.Type == "" {
		return fmt.Errorf("Could not determine certificate type")
	}
	return nil
}
