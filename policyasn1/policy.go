// policyasn1 contains structures required to encode the RFC 5280
// Certificate Policies extension ASN.1 structures.
package policyasn1

import "encoding/asn1"

// CertificatePoliciesExtOID is the OID which identifies the Certificate
// Policies extension, defined as id-ce-certificatePolicies in RFC 5280.
var CertificatePoliciesExtOID = asn1.ObjectIdentifier{2, 5, 29, 32}

// PolicyInformation represents the PolicyInformation ASN.1 structure. It
// excludes the Qualifiers field because that field is NOT RECOMMENDED for all
// certificate profiles in the BRs.
type PolicyInformation struct {
	Policy asn1.ObjectIdentifier
}
