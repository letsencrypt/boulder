package cosigners

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/core/reloid"
)

type testKey struct {
	public *mldsa.PublicKey
	sha256 string
	pem    string
}

// newTestKey generates an ML-DSA-44 key and returns it as cosigners.pem does,
// a comment with the key's SHA-256 followed by its PEM block.
func newTestKey(t *testing.T) testKey {
	t.Helper()
	private, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("GenerateKey: %s", err)
	}
	return pemKey(t, private.PublicKey())
}

func pemKey(t *testing.T, public any) testKey {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %s", err)
	}
	digest := sha256.Sum256(der)
	block := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	mldsaKey, _ := public.(*mldsa.PublicKey)
	return testKey{
		public: mldsaKey,
		sha256: hex.EncodeToString(digest[:]),
		pem:    fmt.Sprintf("# %x\n%s", digest, block),
	}
}

func TestParse(t *testing.T) {
	usable := newTestKey(t)
	candidate := newTestKey(t)
	trusted := newTestKey(t)
	frozen := newTestKey(t)
	cosignersPEM := []byte(usable.pem + candidate.pem + trusted.pem + frozen.pem)
	cosignersJSON := fmt.Appendf(nil, `{
		"timestamp": "2026-10-15T22:30:30Z",
		"version": "2.0.11",
		"operators": [{"name": "Example Operator", "email": ["mtc@example.com"]}],
		"issuers": [{
			"friendly_name": "Example CA",
			"base_id": "32473.1",
			"operator_history": [{"name": "Example Operator", "operator_start": "2026-06-23T00:00:00Z"}],
			"key_sha256": "%s"
		}],
		"mirrors": [
			{
				"friendly_name": "Example Mirror 1",
				"base_id": "32473.9",
				"state_history": [
					{"state": "USABLE", "state_start": "2026-10-01T00:00:00Z"},
					{"state": "QUALIFIED", "state_start": "2026-07-23T00:00:00Z"},
					{"state": "CANDIDATE", "state_start": "2026-06-23T00:00:00Z"}
				],
				"operator_history": [{"name": "Example Operator", "operator_start": "2026-06-23T00:00:00Z"}],
				"base_url": "https://mirror1.example.com/mirror",
				"submission_prefix": "https://mirror1.example.com",
				"type": "MIRROR",
				"realm": "UNTRUSTED_VALIDATION_ONLY",
				"key_sha256": "%s",
				"future_field": true
			},
			{
				"friendly_name": "Example Mirror 2",
				"base_id": "32473.10",
				"state_history": [{"state": "CANDIDATE", "state_start": "2026-10-01T00:00:00Z"}],
				"operator_history": [{"name": "Example Operator", "operator_start": "2026-10-01T00:00:00Z"}],
				"base_url": "https://mirror2.example.com/mirror",
				"submission_prefix": "https://mirror2.example.com",
				"type": "MIRROR",
				"realm": "UNTRUSTED_VALIDATION_ONLY",
				"key_sha256": "%s"
			},
			{
				"friendly_name": "Example Mirror 3",
				"base_id": "32473.11",
				"state_history": [{"state": "USABLE", "state_start": "2026-10-01T00:00:00Z"}],
				"operator_history": [
					{"name": "Other Operator", "operator_start": "2026-10-01T00:00:00Z"},
					{"name": "Example Operator", "operator_start": "2026-06-23T00:00:00Z"}
				],
				"base_url": "https://mirror3.example.com/mirror",
				"submission_prefix": "https://mirror3.example.com",
				"type": "MIRROR",
				"realm": "PUBLICLY_TRUSTED",
				"key_sha256": "%s"
			},
			{
				"friendly_name": "Example Mirror 4",
				"base_id": "32473.12",
				"state_history": [{"state": "FROZEN", "state_start": "2026-10-01T00:00:00Z"}],
				"operator_history": [{"name": "Example Operator", "operator_start": "2026-06-23T00:00:00Z"}],
				"base_url": "https://mirror4.example.com/mirror",
				"type": "MIRROR",
				"realm": "UNTRUSTED_VALIDATION_ONLY",
				"key_sha256": "%s"
			}
		]
	}`, usable.sha256, usable.sha256, candidate.sha256, trusted.sha256, frozen.sha256)

	parsed, err := Parse(cosignersJSON, cosignersPEM)
	if err != nil {
		t.Fatalf("Parse: %s", err)
	}
	if len(parsed.Issuers) != 1 || parsed.Issuers[0].BaseID.String() != "32473.1" || parsed.Issuers[0].Operator != "Example Operator" {
		t.Errorf("Parse returned issuers %v, want Example CA 32473.1 operated by Example Operator", parsed.Issuers)
	}
	mirrors := parsed.Mirrors
	if len(mirrors) != 4 {
		t.Fatalf("Parse returned %d mirrors, want 4", len(mirrors))
	}

	expect := []struct {
		friendlyName     string
		baseID           string
		operator         string
		state            State
		realm            Realm
		submissionPrefix string
		monitoringPrefix string
		key              *mldsa.PublicKey
	}{
		{"Example Mirror 1", "32473.9", "Example Operator", Usable, UntrustedValidationOnly, "https://mirror1.example.com", "https://mirror1.example.com/mirror", usable.public},
		{"Example Mirror 2", "32473.10", "Example Operator", Candidate, UntrustedValidationOnly, "https://mirror2.example.com", "https://mirror2.example.com/mirror", candidate.public},
		{"Example Mirror 3", "32473.11", "Other Operator", Usable, PubliclyTrusted, "https://mirror3.example.com", "https://mirror3.example.com/mirror", trusted.public},
		{"Example Mirror 4", "32473.12", "Example Operator", Frozen, UntrustedValidationOnly, "", "https://mirror4.example.com/mirror", frozen.public},
	}
	for i, m := range mirrors {
		if m.FriendlyName != expect[i].friendlyName {
			t.Errorf("mirror %d FriendlyName = %q, want %q", i, m.FriendlyName, expect[i].friendlyName)
		}
		if m.BaseID.String() != expect[i].baseID {
			t.Errorf("mirror %d BaseID = %s, want %s", i, m.BaseID, expect[i].baseID)
		}
		if m.Operator != expect[i].operator {
			t.Errorf("mirror %d Operator = %q, want %q", i, m.Operator, expect[i].operator)
		}
		if m.State != expect[i].state {
			t.Errorf("mirror %d State = %s, want %s", i, m.State, expect[i].state)
		}
		if m.Realm != expect[i].realm {
			t.Errorf("mirror %d Realm = %q, want %q", i, m.Realm, expect[i].realm)
		}
		if m.SubmissionPrefix != expect[i].submissionPrefix {
			t.Errorf("mirror %d SubmissionPrefix = %q, want %q", i, m.SubmissionPrefix, expect[i].submissionPrefix)
		}
		if m.MonitoringPrefix != expect[i].monitoringPrefix {
			t.Errorf("mirror %d MonitoringPrefix = %q, want %q", i, m.MonitoringPrefix, expect[i].monitoringPrefix)
		}
		if !m.PublicKey.Equal(expect[i].key) {
			t.Errorf("mirror %d PublicKey does not match cosigners.pem", i)
		}
	}
}

func TestParseErrors(t *testing.T) {
	key := newTestKey(t)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %s", err)
	}
	notMLDSA := pemKey(t, &ecdsaKey.PublicKey)
	cosignersPEM := []byte(key.pem + notMLDSA.pem)

	valid := func() jsonSigner {
		return jsonSigner{
			FriendlyName:     "Example Mirror",
			BaseID:           "32473.9",
			StateHistory:     []jsonStateChange{{State: Usable}},
			OperatorHistory:  []jsonOperatorChange{{Name: "Example Operator"}},
			BaseURL:          "https://mirror.example.com/mirror",
			SubmissionPrefix: "https://mirror.example.com",
			Realm:            UntrustedValidationOnly,
			KeySHA256:        key.sha256,
		}
	}

	for _, tc := range []struct {
		name              string
		issuers           []jsonSigner
		mirrors           func() []jsonSigner
		expectErrContains string
	}{
		{
			name:              "issuer with bad base_id",
			issuers:           []jsonSigner{{FriendlyName: "Example CA", BaseID: "not.an.oid", OperatorHistory: []jsonOperatorChange{{Name: "Example Operator"}}}},
			mirrors:           func() []jsonSigner { return []jsonSigner{valid()} },
			expectErrContains: "parsing base_id of issuer \"Example CA\"",
		},
		{
			name:              "issuer with no operator_history",
			issuers:           []jsonSigner{{FriendlyName: "Example CA", BaseID: "32473.1"}},
			mirrors:           func() []jsonSigner { return []jsonSigner{valid()} },
			expectErrContains: "issuer 32473.1 has no operator_history",
		},
		{
			name: "bad base_id",
			mirrors: func() []jsonSigner {
				s := valid()
				s.BaseID = "not.an.oid"
				return []jsonSigner{s}
			},
			expectErrContains: "parsing base_id of mirror \"Example Mirror\"",
		},
		{
			name:              "duplicate base_id",
			mirrors:           func() []jsonSigner { return []jsonSigner{valid(), valid()} },
			expectErrContains: "duplicate base_id 32473.9",
		},
		{
			name: "no operator_history",
			mirrors: func() []jsonSigner {
				s := valid()
				s.OperatorHistory = nil
				return []jsonSigner{s}
			},
			expectErrContains: "mirror 32473.9 has no operator_history",
		},
		{
			name: "no state_history",
			mirrors: func() []jsonSigner {
				s := valid()
				s.StateHistory = nil
				return []jsonSigner{s}
			},
			expectErrContains: "mirror 32473.9 has no state_history",
		},
		{
			name: "unknown state",
			mirrors: func() []jsonSigner {
				s := valid()
				s.StateHistory = []jsonStateChange{{State: "TRUSTED"}}
				return []jsonSigner{s}
			},
			expectErrContains: "mirror 32473.9 has unknown state \"TRUSTED\"",
		},
		{
			name: "no submission_prefix",
			mirrors: func() []jsonSigner {
				s := valid()
				s.SubmissionPrefix = ""
				return []jsonSigner{s}
			},
			expectErrContains: "mirror 32473.9 has no submission_prefix",
		},
		{
			name: "no base_url",
			mirrors: func() []jsonSigner {
				s := valid()
				s.BaseURL = ""
				return []jsonSigner{s}
			},
			expectErrContains: "mirror 32473.9 has no base_url",
		},
		{
			name: "key not in cosigners.pem",
			mirrors: func() []jsonSigner {
				s := valid()
				s.KeySHA256 = strings.Repeat("00", 32)
				return []jsonSigner{s}
			},
			expectErrContains: "is not in cosigners.pem",
		},
		{
			name: "key is not ML-DSA-44",
			mirrors: func() []jsonSigner {
				s := valid()
				s.KeySHA256 = notMLDSA.sha256
				return []jsonSigner{s}
			},
			expectErrContains: "key of mirror 32473.9 is *ecdsa.PublicKey, must be ML-DSA-44",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cosignersJSON, err := json.Marshal(jsonList{Issuers: tc.issuers, Mirrors: tc.mirrors()})
			if err != nil {
				t.Fatalf("json.Marshal: %s", err)
			}
			_, err = Parse(cosignersJSON, cosignersPEM)
			if err == nil {
				t.Fatal("Parse: got nil error, want error")
			}
			if !strings.Contains(err.Error(), tc.expectErrContains) {
				t.Errorf("Parse: got %q, want it to contain %q", err, tc.expectErrContains)
			}
		})
	}

	_, err = Parse([]byte("{"), cosignersPEM)
	if err == nil || !strings.Contains(err.Error(), "parsing cosigners.json") {
		t.Errorf("Parse of malformed JSON: got %s, want parsing cosigners.json error", err)
	}
}

func TestForRealm(t *testing.T) {
	issuers := []*Issuer{{FriendlyName: "Example CA"}}
	input := &List{
		Issuers: issuers,
		Mirrors: []*Mirror{
			{FriendlyName: "Untrusted", Realm: UntrustedValidationOnly},
			{FriendlyName: "Trusted", Realm: PubliclyTrusted},
		},
	}

	trusted, err := input.ForRealm(PubliclyTrusted)
	if err != nil {
		t.Fatalf("ForRealm: %s", err)
	}
	if len(trusted.Mirrors) != 1 || trusted.Mirrors[0].FriendlyName != "Trusted" {
		t.Errorf("ForRealm(PubliclyTrusted) mirrors = %v, want only the Trusted mirror", trusted.Mirrors)
	}
	if len(trusted.Issuers) != 1 || trusted.Issuers[0] != issuers[0] {
		t.Errorf("ForRealm(PubliclyTrusted) issuers = %v, want the list's issuers", trusted.Issuers)
	}

	_, err = input.ForRealm("NO_SUCH_REALM")
	if err == nil {
		t.Error("ForRealm with no mirror in the realm: got nil error, want error")
	}
}

func TestForPurpose(t *testing.T) {
	oid := func(s string) *reloid.RelativeOID {
		t.Helper()
		id, err := reloid.FromString(s)
		if err != nil {
			t.Fatalf("FromString(%q): %s", s, err)
		}
		return id
	}
	input := &List{
		Issuers: []*Issuer{{BaseID: oid("32473.1"), Operator: "Example Operator"}},
		Mirrors: []*Mirror{
			{FriendlyName: "Usable, unaffiliated", BaseID: oid("44947.1"), State: Usable, Operator: "Other Operator"},
			{FriendlyName: "Usable with the CA's PEN", BaseID: oid("32473.9"), State: Usable, Operator: "Other Operator"},
			{FriendlyName: "Usable with the CA's operator", BaseID: oid("44947.2"), State: Usable, Operator: "Example Operator"},
			{FriendlyName: "Candidate", BaseID: oid("44947.3"), State: Candidate, Operator: "Other Operator"},
			{FriendlyName: "Qualified", BaseID: oid("44947.4"), State: Qualified, Operator: "Other Operator"},
			{FriendlyName: "Candidate with the CA's PEN", BaseID: oid("32473.10"), State: Candidate, Operator: "Other Operator"},
			{FriendlyName: "Frozen", BaseID: oid("44947.5"), State: Frozen, Operator: "Other Operator"},
			{FriendlyName: "Removed", BaseID: oid("44947.6"), State: Removed, Operator: "Other Operator"},
			{FriendlyName: "Unset", BaseID: oid("44947.7"), State: Unset, Operator: "Other Operator"},
		},
	}

	for _, tc := range []struct {
		name    string
		purpose purpose
		caID    string
		expect  []string
	}{
		{
			name:    "Cosigning",
			purpose: Cosigning,
			caID:    "32473.1",
			expect:  []string{"Usable, unaffiliated"},
		},
		{
			name:    "SubmissionOnly",
			purpose: SubmissionOnly,
			caID:    "32473.1",
			expect:  []string{"Usable with the CA's PEN", "Usable with the CA's operator", "Candidate", "Qualified", "Candidate with the CA's PEN"},
		},
		{
			name:    "Cosigning for a CA not in the issuers, which has no operator to match",
			purpose: Cosigning,
			caID:    "32473.2",
			expect:  []string{"Usable, unaffiliated", "Usable with the CA's operator"},
		},
		{
			name:    "SubmissionOnly for a CA not in the issuers, which has no operator to match",
			purpose: SubmissionOnly,
			caID:    "32473.2",
			expect:  []string{"Usable with the CA's PEN", "Candidate", "Qualified", "Candidate with the CA's PEN"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var names []string
			for _, m := range input.ForPurpose(tc.purpose, oid(tc.caID)) {
				names = append(names, m.FriendlyName)
			}
			if !slices.Equal(names, tc.expect) {
				t.Errorf("ForPurpose(%s, %s) returned mirrors %q, want %q", tc.purpose, tc.caID, names, tc.expect)
			}
		})
	}
}
