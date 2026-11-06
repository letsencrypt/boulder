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
	"time"

	"github.com/letsencrypt/boulder/core/reloid"
)

// State is a Mirroring Cosigner's inclusion state per CQRP section 3.3.
type State string

// The states, in the order a Mirroring Cosigner enters them. Unset is the
// schema's default.
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

// purpose is a use of a List's mirrors, which accepts some of their states.
type purpose string

// Cosigning accepts only Usable mirrors, the only ones still making the subtree
// signatures CQRP section 2.4.5 lets a standalone certificate carry.
const Cosigning purpose = "cosigning"

// Submission accepts Candidate, Qualified, and Usable mirrors, which CQRP
// section 2.5.1.2 requires a CA to attempt to submit every issuance log update
// to.
const Submission purpose = "submission"

// AcceptedFor reports whether a mirror in state s is accepted for the given
// purpose.
func (s State) AcceptedFor(p purpose) bool {
	switch p {
	case Cosigning:
		return s == Usable
	case Submission:
		return s == Candidate || s == Qualified || s == Usable
	}
	return false
}

// StateChange is an entry of a cosigner's state_history.
type StateChange struct {
	State      State     `json:"state"`
	StateStart time.Time `json:"state_start"`
}

// OperatorChange is an entry of a cosigner's operator_history.
type OperatorChange struct {
	Name          string    `json:"name"`
	OperatorStart time.Time `json:"operator_start"`
}

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
	// OperatorHistory is the issuer's operator_history, in reverse
	// chronological order with the current operator first.
	OperatorHistory []OperatorChange
}

// Operator returns the name of the issuer's current operator.
func (i *Issuer) Operator() string {
	return i.OperatorHistory[0].Name
}

// Mirror is a Mirroring Cosigner from cosigners.json with its public key from
// cosigners.pem.
type Mirror struct {
	FriendlyName string
	// BaseID is the mirror's base_id, its cosigner ID relative to 1.3.6.1.4.1.
	BaseID *reloid.RelativeOID
	// StateHistory is the mirror's state_history, in reverse chronological
	// order with the current state first.
	StateHistory []StateChange
	// OperatorHistory is the mirror's operator_history, in reverse
	// chronological order with the current operator first.
	OperatorHistory  []OperatorChange
	SubmissionPrefix string
	// MonitoringPrefix is the mirror's base_url, its tlog-mirror monitoring
	// prefix. The schema calls it the "Monitoring URL of the cosigner".
	MonitoringPrefix string
	Realm            Realm
	PublicKey        *mldsa.PublicKey
}

// State returns the mirror's current state.
func (m *Mirror) State() State {
	return m.StateHistory[0].State
}

// Operator returns the name of the mirror's current operator.
func (m *Mirror) Operator() string {
	return m.OperatorHistory[0].Name
}

type list struct {
	Issuers []signer `json:"issuers"`
	Mirrors []signer `json:"mirrors"`
}

type signer struct {
	FriendlyName     string           `json:"friendly_name"`
	BaseID           string           `json:"base_id"`
	StateHistory     []StateChange    `json:"state_history"`
	OperatorHistory  []OperatorChange `json:"operator_history"`
	BaseURL          string           `json:"base_url"`
	SubmissionPrefix string           `json:"submission_prefix"`
	Realm            Realm            `json:"realm"`
	KeySHA256        string           `json:"key_sha256"`
}

// Parse returns the List in cosigners.json, with each mirror's ML-DSA-44 public
// key from cosigners.pem, matched by key_sha256. Unknown fields are ignored. A
// submission_prefix is required only of mirrors in a state accepted for
// Submission.
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

	var parsed list
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
			FriendlyName:    s.FriendlyName,
			BaseID:          baseID,
			OperatorHistory: s.OperatorHistory,
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
		if s.SubmissionPrefix == "" && state.AcceptedFor(Submission) {
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
			StateHistory:     s.StateHistory,
			OperatorHistory:  s.OperatorHistory,
			SubmissionPrefix: s.SubmissionPrefix,
			MonitoringPrefix: s.BaseURL,
			Realm:            s.Realm,
			PublicKey:        publicKey,
		})
	}
	return &List{Issuers: issuers, Mirrors: mirrors}, nil
}

// ForPurpose returns the mirrors in realm whose state is accepted for the given
// purpose. It errors if no mirror remains.
func (l *List) ForPurpose(p purpose, realm Realm) ([]*Mirror, error) {
	var res []*Mirror
	for _, m := range l.Mirrors {
		if m.Realm != realm || !m.State().AcceptedFor(p) {
			continue
		}
		res = append(res, m)
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("no mirror in realm %s is in a state accepted for %s", realm, p)
	}
	return res, nil
}

// Affiliated reports whether mirror shares the IANA Private Enterprise Number
// of the CA caID, or has the operator of that CA's entry in the list's issuers.
// CQRP section 2.4.5 requires the mirror subtree signature in a standalone
// certificate to be from a Mirroring Cosigner "not operated by or affiliated
// with the MTC CA Operator".
func (l *List) Affiliated(mirror *Mirror, caID *reloid.RelativeOID) bool {
	if mirror.BaseID.PEN() == caID.PEN() {
		return true
	}
	for _, issuer := range l.Issuers {
		if issuer.BaseID.String() == caID.String() && issuer.Operator() == mirror.Operator() {
			return true
		}
	}
	return false
}
