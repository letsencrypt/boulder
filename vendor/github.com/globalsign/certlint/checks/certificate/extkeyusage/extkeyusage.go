package extkeyusage

import (
	"crypto/x509"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"
)

const checkName = "Extended Key Usage Check"

func init() {
	checks.RegisterCertificateCheck(checkName, nil, Check)
}

// Check verifies if the the required/allowed extended keyusages
// are set in relation to the certificate type.
//
// https://tools.ietf.org/html/rfc5280#section-4.2.1.12
//
func Check(d *certdata.Data) *errors.Errors {
	var e = errors.New(nil)

	if len(d.Cert.ExtKeyUsage) == 0 && len(d.Cert.UnknownExtKeyUsage) == 0 {
		e.Err("Certificate contains no extended key usage")
		return e
	}

	for _, ku := range d.Cert.ExtKeyUsage {
		switch d.Type {
		case "DV", "OV", "EV":
			if ku != x509.ExtKeyUsageServerAuth && ku != x509.ExtKeyUsageClientAuth && ku != x509.ExtKeyUsageMicrosoftServerGatedCrypto {
				e.Err("Certificate contains an extended key usage different from ServerAuth, ClientAuth or ServerGatedCrypto")
				return e
			}
		case "PS":
			if ku != x509.ExtKeyUsageClientAuth && ku != x509.ExtKeyUsageEmailProtection {
				e.Err("Certificate contains an extended key usage different from ClientAuth or EmailProtection")
				return e
			}
		case "CS":
			if ku != x509.ExtKeyUsageCodeSigning {
				e.Err("Certificate contains an extended key usage different from ClientAuth or EmailProtection")
				return e
			}
		}
	}

	if len(d.Cert.UnknownExtKeyUsage) > 0 {
		// encryptedFileSystem 1.3.6.1.4.1.311.10.3.4
		//return fmt.Errorf("%s Certificate contains an unknown extented key usage", d.Type)
	}

	return e
}
