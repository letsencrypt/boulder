// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package boulder

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/url"
	"testing"

	"github.com/bifurcation/gose"
	"github.com/cloudflare/cfssl/signer/local"
)

func TestForbiddenIdentifier(t *testing.T) {
	shouldBeAccepted := []string{
		"www.zombo.com",
		"zombo.com",
		"www.163.com", // Technically disallowed (all-numeric label) but actually common.
		"163.com",
		"zom-bo.com",
		"zombo-.com",
		"www.zom-bo.com",
		"www.zombo-.com",
	}
	shouldBeForbidden := []string{
		"127.0.0.1",
		"10.0.0.10",
		"192.168.1.1",
		"123.45.78.12",
		"",
		"0",
		"1",
		"*",
		"**",
		"*.*",
		"zombo*com",
		"*.com",
		"*.zombo.com",
		".",
		"..",
		"a..",
		"..a",
		".a.",
		".....",
		"www.zombo_com.com",
		"\uFEFF", // Byte order mark
		"\uFEFFwww.zombo.com",
		"www.zömbo.com", // No non-ASCII for now.
		"xn--hmr.net",   // No punycode for now.
		"xn--.net",      // No punycode for now.
		"www.xn--hmr.net",
		"www.zom\u202Ebo.com", // Right-to-Left Override
		"\u202Ewww.zombo.com",
		"www.zom\u200Fbo.com", // Right-to-Left Mark
		"\u200Fwww.zombo.com",
		// 6 * 26 characters = too long for DNS label (max 63).
		"www.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz.com",
		// Labels can't start with dash.
		"www.-ombo.com",
		// Underscores are technically disallowed in DNS. Some DNS
		// implementations accept them but we will be conservative.
		"www.zom_bo.com",
		// All-numeric final label not okay.
		"www.zombo.163",
		"zombocom",
		"a.b.c.d.e.f.g.h.i.j.k", // Too many DNS labels
	}

	for _, identifier := range shouldBeForbidden {
		if !forbiddenIdentifier(identifier) {
			t.Error("Identifier was not correctly forbidden: ", identifier)
		}
	}

	for _, identifier := range shouldBeAccepted {
		if forbiddenIdentifier(identifier) {
			t.Error("Identifier was incorrectly forbidden: ", identifier)
		}
	}
}

type DummyValidationAuthority struct {
	Called   bool
	Argument Authorization
}

func (dva *DummyValidationAuthority) UpdateValidations(authz Authorization) (err error) {
	dva.Called = true
	dva.Argument = authz
	return
}

var (
	// These values we simulate from the client
	AccountKeyJSON = []byte(`{
     "kty": "EC",
     "crv": "P-521",
     "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
     "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"
   }`)
	AccountKey = jose.JsonWebKey{}

	AuthzRequest = Authorization{
		Identifier: AcmeIdentifier{
			Type:  IdentifierDNS,
			Value: "example.com",
		},
	}

	AuthzDelta = Authorization{
		Challenges: map[string]Challenge{
			ChallengeTypeSimpleHTTPS: Challenge{
				Path: "Hf5GrX4Q7EBax9hc2jJnfw",
			},
			ChallengeTypeDVSNI: Challenge{
				S: "23029d88d9e123e",
			},
		},
	}

	ExampleCSR = &x509.CertificateRequest{}

	// These values are populated by the tests as we go
	AuthzInitial  = Authorization{}
	AuthzUpdated  = Authorization{}
	AuthzFromVA   = Authorization{}
	AuthzFinal    = Authorization{}
	AuthzFinalWWW = Authorization{}
)

func initAuthorities(t *testing.T) (CertificateAuthority, *DummyValidationAuthority, *SQLStorageAuthority, RegistrationAuthority) {
	err := json.Unmarshal(AccountKeyJSON, &AccountKey)
	AssertNotError(t, err, "Failed to unmarshall JWK")

	sa, err := NewSQLStorageAuthority("sqlite3", ":memory:")
	AssertNotError(t, err, "Failed to create SA")
	sa.InitTables()

	va := &DummyValidationAuthority{}

	// PEM files in certificate-authority_test.go
	caKeyPEM, _ := pem.Decode([]byte(CA_KEY_PEM))
	caKey, _ := x509.ParsePKCS1PrivateKey(caKeyPEM.Bytes)
	caCertPEM, _ := pem.Decode([]byte(CA_CERT_PEM))
	caCert, _ := x509.ParseCertificate(caCertPEM.Bytes)
	signer, _ := local.NewSigner(caKey, caCert, x509.SHA256WithRSA, nil)
	ca := CertificateAuthorityImpl{signer: signer, SA: sa}
	csrDER, _ := hex.DecodeString(CSR_HEX)
	ExampleCSR, _ = x509.ParseCertificateRequest(csrDER)

	ra := NewRegistrationAuthorityImpl()
	ra.SA = sa
	ra.VA = va
	ra.CA = &ca

	return &ca, va, sa, &ra
}

func assert(t *testing.T, test bool, message string) {
	if !test {
		t.Error(message)
	}
}

func assertAuthzEqual(t *testing.T, a1, a2 Authorization) {
	assert(t, a1.ID == a2.ID, "ret != DB: ID")
	assert(t, a1.Identifier == a2.Identifier, "ret != DB: Identifier")
	assert(t, a1.Status == a2.Status, "ret != DB: Status")
	assert(t, a1.Key.Equals(a2.Key), "ret != DB: Key")
	// Not testing: Contact, Challenges
}

func TestNewAuthorization(t *testing.T) {
	_, _, sa, ra := initAuthorities(t)

	authz, err := ra.NewAuthorization(AuthzRequest, AccountKey)
	AssertNotError(t, err, "NewAuthorization failed")

	// Verify that returned authz same as DB
	dbAuthz, err := sa.GetAuthorization(authz.ID)
	AssertNotError(t, err, "Could not fetch authorization from database")
	assertAuthzEqual(t, authz, dbAuthz)

	// Verify that the returned authz has the right information
	assert(t, authz.Key.Equals(AccountKey), "Initial authz did not get the right key")
	assert(t, authz.Identifier == AuthzRequest.Identifier, "Initial authz had wrong identifier")
	assert(t, authz.Status == StatusPending, "Initial authz not pending")

	_, ok := authz.Challenges[ChallengeTypeDVSNI]
	assert(t, ok, "Initial authz does not include DVSNI challenge")
	_, ok = authz.Challenges[ChallengeTypeSimpleHTTPS]
	assert(t, ok, "Initial authz does not include SimpleHTTPS challenge")

	// If we get to here, we'll use this authorization for the next test
	AuthzInitial = authz

	// TODO Test failure cases
	t.Log("DONE TestNewAuthorization")
}

func TestUpdateAuthorization(t *testing.T) {
	_, va, sa, ra := initAuthorities(t)
	AuthzInitial.ID, _ = sa.NewPendingAuthorization()
	sa.UpdatePendingAuthorization(AuthzInitial)
	AuthzDelta.ID = AuthzInitial.ID

	authz, err := ra.UpdateAuthorization(AuthzDelta)
	AssertNotError(t, err, "UpdateAuthorization failed")

	// Verify that returned authz same as DB
	dbAuthz, err := sa.GetAuthorization(authz.ID)
	AssertNotError(t, err, "Could not fetch authorization from database")
	assertAuthzEqual(t, authz, dbAuthz)

	// Verify that the VA got the authz, and it's the same as the others
	assert(t, va.Called, "Authorization was not passed to the VA")
	assertAuthzEqual(t, authz, va.Argument)

	// Verify that the responses are reflected
	simpleHttps, ok := va.Argument.Challenges[ChallengeTypeSimpleHTTPS]
	simpleHttpsOrig, _ := AuthzDelta.Challenges[ChallengeTypeSimpleHTTPS]
	assert(t, ok, "Authz passed to VA has no simpleHttps challenge")
	assert(t, simpleHttps.Path == simpleHttpsOrig.Path, "simpleHttps changed")
	dvsni, ok := va.Argument.Challenges[ChallengeTypeDVSNI]
	dvsniOrig, _ := AuthzDelta.Challenges[ChallengeTypeDVSNI]
	assert(t, ok, "Authz passed to VA has no dvsni challenge")
	assert(t, dvsni.Token == dvsniOrig.Token, "dvsni changed")

	// If we get to here, we'll use this authorization for the next test
	AuthzUpdated = authz

	// TODO Test failure cases
	t.Log("DONE TestUpdateAuthorization")
}

func TestOnValidationUpdate(t *testing.T) {
	_, _, sa, ra := initAuthorities(t)
	AuthzUpdated.ID, _ = sa.NewPendingAuthorization()
	sa.UpdatePendingAuthorization(AuthzUpdated)

	// Simulate a successful simpleHttps challenge
	AuthzFromVA = AuthzUpdated
	challenge := AuthzFromVA.Challenges[ChallengeTypeSimpleHTTPS]
	challenge.Status = StatusValid
	AuthzFromVA.Challenges[ChallengeTypeSimpleHTTPS] = challenge

	ra.OnValidationUpdate(AuthzFromVA)

	// Verify that the Authz in the DB is the same except for Status->StatusValid
	AuthzFromVA.Status = StatusValid
	dbAuthz, err := sa.GetAuthorization(AuthzFromVA.ID)
	AssertNotError(t, err, "Could not fetch authorization from database")
	assertAuthzEqual(t, AuthzFromVA, dbAuthz)
	t.Log(" ~~> from VA: ", AuthzFromVA.Status)
	t.Log(" ~~> from DB: ", dbAuthz.Status)

	// If we get to here, we'll use this authorization for the next test
	AuthzFinal = dbAuthz

	// TODO Test failure cases
	t.Log("DONE TestOnValidationUpdate")
}

func TestNewCertificate(t *testing.T) {
	_, _, sa, ra := initAuthorities(t)
	AuthzFinal.ID, _ = sa.NewPendingAuthorization()
	sa.UpdatePendingAuthorization(AuthzFinal)
	sa.FinalizeAuthorization(AuthzFinal)

	// Inject another final authorization to cover www.example.com
	AuthzFinalWWW = AuthzFinal
	AuthzFinalWWW.Identifier.Value = "www.example.com"
	AuthzFinalWWW.ID, _ = sa.NewPendingAuthorization()
	sa.FinalizeAuthorization(AuthzFinalWWW)

	// Construct a cert request referencing the two authorizations
	url1, _ := url.Parse("http://doesnt.matter/" + AuthzFinal.ID)
	url2, _ := url.Parse("http://doesnt.matter/" + AuthzFinalWWW.ID)
	certRequest := CertificateRequest{
		CSR:            ExampleCSR,
		Authorizations: []AcmeURL{AcmeURL(*url1), AcmeURL(*url2)},
	}

	cert, err := ra.NewCertificate(certRequest, AccountKey)
	AssertNotError(t, err, "Failed to issue certificate")

	// Verify that cert shows up and is as expected
	dbCert, err := sa.GetCertificate(cert.ID)
	AssertNotError(t, err, "Could not fetch certificate from database")
	assert(t, bytes.Compare(cert.DER, dbCert) == 0, "Certificates differ")

	// TODO Test failure cases
	t.Log("DONE TestOnValidationUpdate")
}
