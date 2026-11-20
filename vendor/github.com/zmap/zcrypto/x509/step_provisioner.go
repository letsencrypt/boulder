package x509

import (
	"encoding/json"
	"strconv"
)

// Smallstep step-ca provisioner types, as defined by step-ca in
// authority/provisioner.Type. The extension records the type as an integer;
// these names are used when rendering it as JSON.
const (
	stepProvisionerJWK    = 1
	stepProvisionerOIDC   = 2
	stepProvisionerGCP    = 3
	stepProvisionerAWS    = 4
	stepProvisionerAzure  = 5
	stepProvisionerACME   = 6
	stepProvisionerX5C    = 7
	stepProvisionerK8sSA  = 8
	stepProvisionerSSHPOP = 9
	stepProvisionerSCEP   = 10
	stepProvisionerNebula = 11
)

// StepProvisioner is the Smallstep step-ca provisioner extension, identified
// by OID 1.3.6.1.4.1.37476.9000.64.1. step-ca stamps this extension onto the
// certificates it issues in order to record which provisioner authorized the
// issuance.
//
// The extension is not described by any standard. The structure below follows
// step-ca's own encoding: a provisioner type, a provisioner name, an optional
// credential identifier, and an optional flat list of alternating keys and
// values carrying provisioner-specific metadata.
type StepProvisioner struct {
	Type          int
	Name          []byte
	CredentialID  []byte
	KeyValuePairs []string `asn1:"optional,omitempty"`
}

// stepProvisionerTypeName returns the step-ca name for a provisioner type, or
// a decimal rendering of the raw value if the type is not one this package
// knows about.
func stepProvisionerTypeName(t int) string {
	switch t {
	case stepProvisionerJWK:
		return "JWK"
	case stepProvisionerOIDC:
		return "OIDC"
	case stepProvisionerGCP:
		return "GCP"
	case stepProvisionerAWS:
		return "AWS"
	case stepProvisionerAzure:
		return "Azure"
	case stepProvisionerACME:
		return "ACME"
	case stepProvisionerX5C:
		return "X5C"
	case stepProvisionerK8sSA:
		return "K8sSA"
	case stepProvisionerSSHPOP:
		return "SSHPOP"
	case stepProvisionerSCEP:
		return "SCEP"
	case stepProvisionerNebula:
		return "Nebula"
	default:
		return "unknown (" + strconv.Itoa(t) + ")"
	}
}

// jsonStepProvisioner is the JSON representation of a StepProvisioner.
type jsonStepProvisioner struct {
	Type          string            `json:"type"`
	Name          string            `json:"name"`
	CredentialID  string            `json:"credential_id,omitempty"`
	KeyValuePairs map[string]string `json:"key_value_pairs,omitempty"`
}

// MarshalJSON implements the json.Marshaler interface. The provisioner type is
// rendered by name, and the flat list of alternating keys and values is
// rendered as an object. A trailing key with no value is given an empty value.
func (sp *StepProvisioner) MarshalJSON() ([]byte, error) {
	out := jsonStepProvisioner{
		Type: stepProvisionerTypeName(sp.Type),
		Name: string(sp.Name),
	}
	if len(sp.CredentialID) > 0 {
		out.CredentialID = string(sp.CredentialID)
	}
	if len(sp.KeyValuePairs) > 0 {
		out.KeyValuePairs = make(map[string]string, (len(sp.KeyValuePairs)+1)/2)
		for i := 0; i < len(sp.KeyValuePairs); i += 2 {
			var value string
			if i+1 < len(sp.KeyValuePairs) {
				value = sp.KeyValuePairs[i+1]
			}
			out.KeyValuePairs[sp.KeyValuePairs[i]] = value
		}
	}
	return json.Marshal(out)
}
