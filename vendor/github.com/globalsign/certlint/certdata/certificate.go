package certdata

import (
	"crypto/x509"
	"fmt"
)

// Data holds the certificate and relevant information
// Type can be DV, OV, EV, PS, CS, EVCS, TS, OCSP, CA
type Data struct {
	Cert   *x509.Certificate
	Issuer *x509.Certificate
	Type   string
}

// Load raw certificate bytes into a Data struct
func Load(der []byte) (*Data, error) {
	var err error

	d := new(Data)
	d.Cert, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	if err = d.setCertificateType(); err != nil {
		fmt.Println(err)
	}

	return d, nil
}

// SetIssuer sets the issuer of a certificate
// TODO: Validate if the correct issuer is given
func (d *Data) SetIssuer(der []byte) error {
	var err error
	d.Issuer, err = x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	return nil
}
