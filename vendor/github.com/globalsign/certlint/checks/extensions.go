package checks

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
	"sync"

	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/errors"
)

var extMutex = &sync.Mutex{}

type extensions []extensionCheck

type extensionCheck struct {
	name   string
	oid    asn1.ObjectIdentifier
	filter *Filter
	f      func(pkix.Extension, *certdata.Data) *errors.Errors
}

// Extensions contains all imported extension checks
var Extensions extensions

// RegisterExtensionCheck adds a new check to Extensions
func RegisterExtensionCheck(name string, oid asn1.ObjectIdentifier, filter *Filter, f func(pkix.Extension, *certdata.Data) *errors.Errors) {
	extMutex.Lock()
	Extensions = append(Extensions, extensionCheck{name, oid, filter, f})
	extMutex.Unlock()
}

// Check lookups the registered extension checks and runs all checks with the
// same Object Identifier.
func (ex extensions) Check(ext pkix.Extension, d *certdata.Data) *errors.Errors {
	var e = errors.New(nil)
	var found bool

	for _, ec := range ex {
		if ec.oid.Equal(ext.Id) {
			found = true
			if ec.filter != nil && ec.filter.Check(d) {
				continue
			}
			e.Append(ec.f(ext, d))
		}
	}

	if !found {
		// Don't report private enterprise extensions as unknown, registered private
		// extensions have still been checked above.
		if !strings.HasPrefix(ext.Id.String(), "1.3.6.1.4.1.") {
			e.Warning("Certificate contains unknown extension (%s)", ext.Id.String())
		}
	}

	return e
}
