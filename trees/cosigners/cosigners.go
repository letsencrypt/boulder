// Package cosigners parses the Chrome Quantum-resistant Root Program's cosigner
// list, cosigners.json, and the matching public keys in cosigners.pem.
//
//   - https://www.gstatic.com/mtcs/cosigners/v1/cosigners.json
//   - https://www.gstatic.com/mtcs/cosigners/v1/cosigners.pem
//   - https://www.gstatic.com/mtcs/cosigners/v1/cosigners_schema.json
package cosigners

import (
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"slices"

	"github.com/letsencrypt/boulder/core/reloid"
)

// State is a Mirroring Cosigner's inclusion state per CQRP section 3.3.
type State string

// The states, in the order a Mirroring Cosigner enters them. Unset is in the
// schema but not in the CQRP.
const (
	Unset     State = "UNSET"
	Candidate State = "CANDIDATE"
	Qualified State = "QUALIFIED"
	Usable    State = "USABLE"
	Frozen    State = "FROZEN"
	Removed   State = "REMOVED"
)

// Realm is a cosigner's authentication realm. Only PubliclyTrusted cosigners
// are trusted by default in Chrome.
type Realm string

const (
	UntrustedValidationOnly Realm = "UNTRUSTED_VALIDATION_ONLY"
	PubliclyTrusted         Realm = "PUBLICLY_TRUSTED"
)

// List is the cosigner list parsed from cosigners.json.
type List struct {
	Issuers []*Issuer
	Mirrors []*Mirror
}

// Issuer is an MTC CA's issuance log from cosigners.json.
type Issuer struct {
	FriendlyName string
	// BaseID is the issuer's base_id, its CA ID relative to 1.3.6.1.4.1.
	BaseID *reloid.RelativeOID
	// Operator is the name of the issuer's current operator, the first entry
	// of its operator_history.
	Operator string
}

// Mirror is a Mirroring Cosigner from cosigners.json with its public key from
// cosigners.pem.
type Mirror struct {
	FriendlyName string
	// BaseID is the mirror's base_id, its cosigner ID relative to 1.3.6.1.4.1.
	BaseID *reloid.RelativeOID
	// State is the mirror's current state, the first entry of its
	// state_history.
	State State
	// Operator is the name of the mirror's current operator, the first entry
	// of its operator_history.
	Operator         string
	SubmissionPrefix string
	// MonitoringPrefix is the mirror's base_url, its tlog-mirror monitoring
	// prefix. The schema calls it the "Monitoring URL of the cosigner".
	MonitoringPrefix string
	Realm            Realm
	PublicKey        *mldsa.PublicKey
}

// The types below follow the cosigners.json schema. Parse unmarshals into them
// and nothing else uses them, so that List, Issuer, and Mirror hold only what
// their callers read.
type jsonList struct {
	Issuers []jsonSigner `json:"issuers"`
	Mirrors []jsonSigner `json:"mirrors"`
}

type jsonSigner struct {
	FriendlyName     string               `json:"friendly_name"`
	BaseID           string               `json:"base_id"`
	StateHistory     []jsonStateChange    `json:"state_history"`
	OperatorHistory  []jsonOperatorChange `json:"operator_history"`
	BaseURL          string               `json:"base_url"`
	SubmissionPrefix string               `json:"submission_prefix"`
	Realm            Realm                `json:"realm"`
	KeySHA256        string               `json:"key_sha256"`
}

// jsonStateChange is an entry of a signer's state_history, which is in reverse
// chronological order with the current state first.
type jsonStateChange struct {
	State State `json:"state"`
}

// jsonOperatorChange is an entry of a signer's operator_history, which is in
// reverse chronological order with the current operator first.
type jsonOperatorChange struct {
	Name string `json:"name"`
}

// Parse returns the List in cosigners.json, with each mirror's ML-DSA-44 public
// key from cosigners.pem, matched by key_sha256. Unknown fields are ignored. A
// submission_prefix is required only of mirrors in a state that CQRP section
// 2.5.1.2 requires a CA to submit to.
func Parse(cosignersJSON, cosignersPEM []byte) (*List, error) {
	keys := make(map[string][]byte)
	rest := cosignersPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "PUBLIC KEY" {
			continue
		}
		digest := sha256.Sum256(block.Bytes)
		keys[hex.EncodeToString(digest[:])] = block.Bytes
	}

	var parsed jsonList
	err := json.Unmarshal(cosignersJSON, &parsed)
	if err != nil {
		return nil, fmt.Errorf("parsing cosigners.json: %s", err)
	}

	var issuers []*Issuer
	for _, s := range parsed.Issuers {
		baseID, err := reloid.FromString(s.BaseID)
		if err != nil {
			return nil, fmt.Errorf("parsing base_id of issuer %q: %s", s.FriendlyName, err)
		}
		if len(s.OperatorHistory) == 0 {
			return nil, fmt.Errorf("issuer %s has no operator_history", s.BaseID)
		}
		issuers = append(issuers, &Issuer{
			FriendlyName: s.FriendlyName,
			BaseID:       baseID,
			Operator:     s.OperatorHistory[0].Name,
		})
	}

	var mirrors []*Mirror
	seen := make(map[string]bool)
	for _, s := range parsed.Mirrors {
		baseID, err := reloid.FromString(s.BaseID)
		if err != nil {
			return nil, fmt.Errorf("parsing base_id of mirror %q: %s", s.FriendlyName, err)
		}
		if seen[baseID.String()] {
			return nil, fmt.Errorf("duplicate base_id %s", baseID)
		}
		seen[baseID.String()] = true
		if len(s.OperatorHistory) == 0 {
			return nil, fmt.Errorf("mirror %s has no operator_history", s.BaseID)
		}
		if len(s.StateHistory) == 0 {
			return nil, fmt.Errorf("mirror %s has no state_history", s.BaseID)
		}
		state := s.StateHistory[0].State
		switch state {
		case Unset, Candidate, Qualified, Usable, Frozen, Removed:
		default:
			return nil, fmt.Errorf("mirror %s has unknown state %q", s.BaseID, state)
		}
		if s.SubmissionPrefix == "" && state.acceptsSubmissions() {
			return nil, fmt.Errorf("mirror %s has no submission_prefix", s.BaseID)
		}
		if s.BaseURL == "" {
			return nil, fmt.Errorf("mirror %s has no base_url", s.BaseID)
		}
		der, ok := keys[s.KeySHA256]
		if !ok {
			return nil, fmt.Errorf("mirror %s key_sha256 %q is not in cosigners.pem", s.BaseID, s.KeySHA256)
		}
		key, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, fmt.Errorf("parsing key of mirror %s: %s", s.BaseID, err)
		}
		publicKey, ok := key.(*mldsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key of mirror %s is %T, must be ML-DSA-44", s.BaseID, key)
		}
		if publicKey.Parameters().PublicKeySize() != mldsa.MLDSA44PublicKeySize {
			return nil, fmt.Errorf("key of mirror %s is %s, must be ML-DSA-44", s.BaseID, publicKey.Parameters())
		}
		mirrors = append(mirrors, &Mirror{
			FriendlyName:     s.FriendlyName,
			BaseID:           baseID,
			State:            state,
			Operator:         s.OperatorHistory[0].Name,
			SubmissionPrefix: s.SubmissionPrefix,
			MonitoringPrefix: s.BaseURL,
			Realm:            s.Realm,
			PublicKey:        publicKey,
		})
	}
	return &List{Issuers: issuers, Mirrors: mirrors}, nil
}

// ForRealm returns the list with only its mirrors in realm. It errors if there
// are none.
func (l *List) ForRealm(realm Realm) (*List, error) {
	var mirrors []*Mirror
	for _, m := range l.Mirrors {
		if m.Realm == realm {
			mirrors = append(mirrors, m)
		}
	}
	if len(mirrors) == 0 {
		return nil, fmt.Errorf("no mirror is in realm %s", realm)
	}
	return &List{Issuers: l.Issuers, Mirrors: mirrors}, nil
}

// purpose is what a CA uses a mirror for. The purposes are not part of
// cosigners.json. They are this package's reading of what the CQRP lets a CA
// do with a mirror, given the mirror's state and operator.
type purpose string

const (
	// Cosigning mirrors are submitted to, and their cosignatures are stored
	// for use in standalone certificates. CQRP section 2.4.5 requires those
	// to be from a Usable mirror "not operated by or affiliated with the MTC
	// CA Operator". It also allows a Frozen mirror's cosignature "generated
	// prior to the freeze point", but a Frozen mirror makes no new ones.
	Cosigning purpose = "cosigning"

	// SubmissionOnly mirrors are submitted to, but their cosignatures are not
	// stored. They are the Candidate, Qualified, and Usable mirrors that are
	// not Cosigning mirrors. CQRP section 2.5.1.2 requires a CA to attempt to
	// submit every issuance log update to all mirrors in those states.
	SubmissionOnly purpose = "submission only"
)

// acceptsSubmissions reports whether a mirror in state s is one CQRP section
// 2.5.1.2 requires a CA to submit to.
func (s State) acceptsSubmissions() bool {
	return s == Candidate || s == Qualified || s == Usable
}

// ForPurpose returns the mirrors that the CA caID uses for the given purpose.
// No mirror is returned for both purposes. A mirror is affiliated with the CA
// if it shares the CA's IANA Private Enterprise Number, or has the operator of
// the CA's entry in the list's issuers.
func (l *List) ForPurpose(p purpose, caID *reloid.RelativeOID) []*Mirror {
	var mirrors []*Mirror
	for _, m := range l.Mirrors {
		affiliated := m.BaseID.PEN() == caID.PEN() || slices.ContainsFunc(l.Issuers, func(issuer *Issuer) bool {
			return issuer.BaseID.String() == caID.String() && issuer.Operator == m.Operator
		})
		cosigning := m.State == Usable && !affiliated
		switch {
		case p == Cosigning && cosigning:
			mirrors = append(mirrors, m)
		case p == SubmissionOnly && !cosigning && m.State.acceptsSubmissions():
			mirrors = append(mirrors, m)
		}
	}
	return mirrors
}
