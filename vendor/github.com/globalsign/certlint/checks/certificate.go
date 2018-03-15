package checks

import (
	"sync"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/errors"
)

var certMutex = &sync.Mutex{}

type certificate []certificateCheck

type certificateCheck struct {
	name   string
	filter *Filter
	f      func(*certdata.Data) *errors.Errors
}

// Certificate contains all imported certificate checks
var Certificate certificate

// RegisterCertificateCheck adds a new check to Cerificates
func RegisterCertificateCheck(name string, filter *Filter, f func(*certdata.Data) *errors.Errors) {
	certMutex.Lock()
	Certificate = append(Certificate, certificateCheck{name, filter, f})
	certMutex.Unlock()
}

// Check runs all the registered certificate checks
func (c certificate) Check(d *certdata.Data) *errors.Errors {
	var e = errors.New(nil)

	for _, cc := range c {
		if cc.filter != nil && !cc.filter.Check(d) {
			continue
		}
		e.Append(cc.f(d))
	}

	return e
}
