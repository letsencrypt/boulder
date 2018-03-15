package asn1

import (
	"encoding/asn1"

	"github.com/globalsign/certlint/errors"
)

type Linter struct {
	e errors.Errors
}

// CheckStruct returns a list of errors based on strict checks on the raw ASN1
// encoding of the input der.
func (l *Linter) CheckStruct(der []byte) *errors.Errors {
	l.walk(der)
	if l.e.IsError() {
		return &l.e
	}
	return nil
}

// walk is a recursive call that walks over the ASN1 structured data until no
// remaining bytes are left. For each non compound is will call the ASN1 format
// checker.
func (l *Linter) walk(der []byte) {
	var err error
	var d asn1.RawValue

	for len(der) > 0 {
		der, err = asn1.Unmarshal(der, &d)
		if err != nil {
			// Errors should be included in the report, but allow format checking when
			// data has been decoded.
			l.e.Err(err.Error())
			if len(d.Bytes) == 0 {
				return
			}
		}

		// A compound is an ASN.1 container that contains other structs.
		if d.IsCompound {
			l.walk(d.Bytes)
		} else {
			l.CheckFormat(d)
		}
	}
}
