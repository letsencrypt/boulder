package internal

import (
	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"
)

const checkName = "Internal Names and IP addresses Check"

func init() {
	filter := &checks.Filter{
		Type: []string{"DV", "OV", "IV", "EV"},
	}
	checks.RegisterCertificateCheck(checkName, filter, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
// TODO: Add more checks https://golang.org/src/crypto/x509/x509.go?s=15439:18344#L1157
func Check(d *certdata.Data) *errors.Errors {
	var e = errors.New(nil)

	if checkInternalName(d.Cert.Subject.CommonName) {
		e.Err("Certificate contains an internal server name in the common name '%s'", d.Cert.Subject.CommonName)
	}
	for _, n := range d.Cert.DNSNames {
		if checkInternalName(n) {
			e.Err("Certificate subjectAltName '%s' contains an internal server name", n)
		}
	}

	// Check for internal IP addresses
	for _, ip := range d.Cert.IPAddresses {
		if !ip.IsGlobalUnicast() {
			e.Err("Certificate subjectAltName '%v' contains a non global unicast IP address", ip)
		}
		if checkInternalIP(ip) {
			e.Err("Certificate subjectAltName '%v' contains a private or local IP address", ip)
		}
	}

	return e
}
