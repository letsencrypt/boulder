package subscriber

import (
	"encoding/asn1"
	"encoding/json"
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"github.com/letsencrypt/boulder/linter/lints"
)

type isrgDomainValidated struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_isrg_domain_validated_oid",
		Description:   "Let's Encrypt Domain Validated Subscriber Certificates contain the ISRG Domain Validated OID",
		Citation:      "CPS: 7.1",
		Source:        lints.LetsEncryptCPSSubscriber,
		EffectiveDate: lints.CPSV33Date,
		Lint:          NewISRGDomainValidatedOID,
	})
}

func NewISRGDomainValidatedOID() lint.LintInterface {
	return &isrgDomainValidated{}
}

func (l *isrgDomainValidated) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && !c.IsCA
}

type Extension struct {
	Id       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

type Extensions struct {
	Extensions []Extension
}

func getExtWithOID(exts []Extension, oid asn1.ObjectIdentifier) bool {
	for _, ext := range exts {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}

func (l *isrgDomainValidated) Execute(c *x509.Certificate) *lint.LintResult {
	isrgDVOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44947, 1, 1, 1}

	targetStruct := Extensions{}
	origStruct, _ := json.Marshal(c.Extensions)
	err := json.Unmarshal(origStruct, &targetStruct)
	if err != nil {
		fmt.Println("something is wrong!")
	}
	if !getExtWithOID(targetStruct.Extensions, isrgDVOID) {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Certificate does not contain ISRG Domain Validated OID",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
