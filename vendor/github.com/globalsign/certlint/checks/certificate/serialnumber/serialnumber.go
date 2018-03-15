package serialnumber

import (
	"math/big"
	"time"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	"github.com/globalsign/certlint/errors"
)

const checkName = "Certificate Serial Number Check"

func init() {
	checks.RegisterCertificateCheck(checkName, nil, Check)
}

// Check performs a strict verification on the extension according to the standard(s)
func Check(d *certdata.Data) *errors.Errors {
	var e = errors.New(nil)

	if d.Cert.SerialNumber.Cmp(big.NewInt(0)) == -1 {
		e.Err("Certificate serial number MUST be a positive integer (%d)", d.Cert.SerialNumber)
	}

	// Remaining checks are not relevant for CA certificates
	if d.Cert.IsCA {
		return e
	}

	// https://cabforum.org/2016/07/08/ballot-164/
	if d.Cert.NotBefore.After(time.Date(2016, 9, 30, 0, 0, 0, 0, time.UTC)) {
		if d.Cert.SerialNumber.BitLen() < 64 {
			e.Err("Certificate serial number should be 64 bits but contains %d bits", d.Cert.SerialNumber.BitLen())
		}
	} else {
		// all new end-entity certificates must contain at least 20 bits of unpredictable random data (preferably in the serial number).
		if d.Cert.SerialNumber.BitLen() < 20 {
			e.Warning("Certificate serial number must contain at least 20 bits of unpredictable random data, found only %d bits", d.Cert.SerialNumber.BitLen())
		}
	}

	return nil
}
