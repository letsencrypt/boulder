// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ra

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	cfsslConfig "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/config"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/ocsp"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/signer/local"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"
	"github.com/letsencrypt/boulder/ca"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/policy"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test"
)

type DummyValidationAuthority struct {
	Called   bool
	Argument core.Authorization
}

func (dva *DummyValidationAuthority) UpdateValidations(authz core.Authorization, index int) (err error) {
	dva.Called = true
	dva.Argument = authz
	return
}

func (dva *DummyValidationAuthority) CheckCAARecords(identifier core.AcmeIdentifier) (present, valid bool, err error) {
	return false, true, nil
}

var (
	// These values we simulate from the client
	AccountKeyJSONA = []byte(`{
		"kty":"RSA",
		"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":"AQAB"
	}`)
	AccountKeyA = jose.JsonWebKey{}

	AccountKeyJSONB = []byte(`{
		"kty":"RSA",
		"n":"z8bp-jPtHt4lKBqepeKF28g_QAEOuEsCIou6sZ9ndsQsEjxEOQxQ0xNOQezsKa63eogw8YS3vzjUcPP5BJuVzfPfGd5NVUdT-vSSwxk3wvk_jtNqhrpcoG0elRPQfMVsQWmxCAXCVRz3xbcFI8GTe-syynG3l-g1IzYIIZVNI6jdljCZML1HOMTTW4f7uJJ8mM-08oQCeHbr5ejK7O2yMSSYxW03zY-Tj1iVEebROeMv6IEEJNFSS4yM-hLpNAqVuQxFGetwtwjDMC1Drs1dTWrPuUAAjKGrP151z1_dE74M5evpAhZUmpKv1hY-x85DC6N0hFPgowsanmTNNiV75w",
		"e":"AQAB"
	}`)
	AccountKeyB = jose.JsonWebKey{}

	AccountKeyJSONC = []byte(`{
		"kty":"RSA",
		"n":"rFH5kUBZrlPj73epjJjyCxzVzZuV--JjKgapoqm9pOuOt20BUTdHqVfC2oDclqM7HFhkkX9OSJMTHgZ7WaVqZv9u1X2yjdx9oVmMLuspX7EytW_ZKDZSzL-sCOFCuQAuYKkLbsdcA3eHBK_lwc4zwdeHFMKIulNvLqckkqYB9s8GpgNXBDIQ8GjR5HuJke_WUNjYHSd8jY1LU9swKWsLQe2YoQUz_ekQvBvBCoaFEtrtRaSJKNLIVDObXFr2TLIiFiM0Em90kK01-eQ7ZiruZTKomll64bRFPoNo4_uwubddg3xTqur2vdF3NyhTrYdvAgTem4uC0PFjEQ1bK_djBQ",
		"e":"AQAB"
	}`)
	AccountKeyC = jose.JsonWebKey{}

	// These values we simulate from the client
	AccountPrivateKeyJSON = []byte(`{
		"kty":"RSA",
		"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":"AQAB",
		"d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
		"p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
		"q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
		"dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
		"dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
		"qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU"
	}`)
	AccountPrivateKey = jose.JsonWebKey{}

	ShortKeyJSON = []byte(`{
		"e": "AQAB",
		"kty": "RSA",
		"n": "tSwgy3ORGvc7YJI9B2qqkelZRUC6F1S5NwXFvM4w5-M0TsxbFsH5UH6adigV0jzsDJ5imAechcSoOhAh9POceCbPN1sTNwLpNbOLiQQ7RD5mY_"
		}`)

	ShortKey = jose.JsonWebKey{}

	AuthzRequest = core.Authorization{
		Identifier: core.AcmeIdentifier{
			Type:  core.IdentifierDNS,
			Value: "not-example.com",
		},
	}

	ResponseIndex = 0
	Response      = core.Challenge{
		Type: "simpleHttp",
	}

	ExampleCSR = &x509.CertificateRequest{}

	// These values are populated by the tests as we go
	url0, _      = url.Parse("http://acme.invalid/authz/60p2Dc_XmUB2UUJBV4wYkF7BJbPD9KlDnUL3SmFMuTE?challenge=0")
	url1, _      = url.Parse("http://acme.invalid/authz/60p2Dc_XmUB2UUJBV4wYkF7BJbPD9KlDnUL3SmFMuTE?challenge=0")
	Registration = core.Registration{}
	AuthzInitial = core.Authorization{
		ID:             "60p2Dc_XmUB2UUJBV4wYkF7BJbPD9KlDnUL3SmFMuTE",
		Identifier:     core.AcmeIdentifier{Type: "dns", Value: "not-example.com"},
		RegistrationID: 1,
		Status:         "pending",
		Challenges: []core.Challenge{
			core.SimpleHTTPChallenge(),
			core.DvsniChallenge(),
		},
		Combinations: [][]int{[]int{0}, []int{1}},
	}
	AuthzFinal = core.Authorization{}

	log = mocks.UseMockLog()
)

const (
	paDBConnStr = "mysql+tcp://boulder@localhost:3306/boulder_policy_test"
	saDBConnStr = "mysql+tcp://boulder@localhost:3306/boulder_sa_test"
)

func initAuthorities(t *testing.T) (*DummyValidationAuthority, *sa.SQLStorageAuthority, *RegistrationAuthorityImpl, clock.FakeClock, func()) {
	err := json.Unmarshal(AccountKeyJSONA, &AccountKeyA)
	test.AssertNotError(t, err, "Failed to unmarshal public JWK")
	err = json.Unmarshal(AccountKeyJSONB, &AccountKeyB)
	test.AssertNotError(t, err, "Failed to unmarshal public JWK")
	err = json.Unmarshal(AccountKeyJSONC, &AccountKeyC)
	test.AssertNotError(t, err, "Failed to unmarshal public JWK")

	err = json.Unmarshal(AccountPrivateKeyJSON, &AccountPrivateKey)
	test.AssertNotError(t, err, "Failed to unmarshal private JWK")

	err = json.Unmarshal(ShortKeyJSON, &ShortKey)
	test.AssertNotError(t, err, "Failed to unmarshall JWK")

	fc := clock.NewFake()

	dbMap, err := sa.NewDbMap(saDBConnStr)
	if err != nil {
		t.Fatalf("Failed to create dbMap: %s", err)
	}
	ssa, err := sa.NewSQLStorageAuthority(dbMap, fc)
	if err != nil {
		t.Fatalf("Failed to create SA: %s", err)
	}

	saDBCleanUp := test.ResetTestDatabase(t, dbMap.Db)

	va := &DummyValidationAuthority{}

	// PEM files in certificate-authority_test.go
	caKeyPEM, _ := pem.Decode([]byte(CAkeyPEM))
	caKey, _ := x509.ParsePKCS1PrivateKey(caKeyPEM.Bytes)
	caCertPEM, _ := pem.Decode([]byte(CAcertPEM))
	caCert, _ := x509.ParseCertificate(caCertPEM.Bytes)
	basicPolicy := &cfsslConfig.Signing{
		Default: &cfsslConfig.SigningProfile{
			Usage:  []string{"server auth", "client auth"},
			Expiry: 1 * time.Hour,
			CSRWhitelist: &cfsslConfig.CSRWhitelist{
				PublicKey:          true,
				PublicKeyAlgorithm: true,
				SignatureAlgorithm: true,
				DNSNames:           true,
			},
		},
	}
	signer, _ := local.NewSigner(caKey, caCert, x509.SHA256WithRSA, basicPolicy)
	ocspSigner, _ := ocsp.NewSigner(caCert, caCert, caKey, time.Hour)
	paDbMap, err := sa.NewDbMap(paDBConnStr)
	if err != nil {
		t.Fatalf("Failed to create dbMap: %s", err)
	}
	policyDBCleanUp := test.ResetTestDatabase(t, paDbMap.Db)
	pa, err := policy.NewPolicyAuthorityImpl(paDbMap, false)
	test.AssertNotError(t, err, "Couldn't create PA")
	ca := ca.CertificateAuthorityImpl{
		Signer:         signer,
		OCSPSigner:     ocspSigner,
		SA:             ssa,
		PA:             pa,
		ValidityPeriod: time.Hour * 2190,
		NotAfter:       time.Now().Add(time.Hour * 8761),
		Clk:            fc,
		Publisher:      &mocks.MockPublisher{},
	}
	cleanUp := func() {
		saDBCleanUp()
		policyDBCleanUp()
	}

	csrDER, _ := hex.DecodeString(CSRhex)
	ExampleCSR, _ = x509.ParseCertificateRequest(csrDER)

	Registration, _ = ssa.NewRegistration(core.Registration{Key: AccountKeyA})

	stats, _ := statsd.NewNoopClient()
	ra := NewRegistrationAuthorityImpl(fc, blog.GetAuditLogger(), stats, cmd.RateLimitConfig{
		TotalCertificates: cmd.RateLimitPolicy{
			Threshold: 100,
			Window:    cmd.ConfigDuration{Duration: 24 * 90 * time.Hour},
		},
	})
	ra.SA = ssa
	ra.VA = va
	ra.CA = &ca
	ra.PA = pa
	ra.DNSResolver = &mocks.MockDNS{}

	AuthzInitial.RegistrationID = Registration.ID

	AuthzFinal = AuthzInitial
	AuthzFinal.Status = "valid"
	exp := time.Now().Add(365 * 24 * time.Hour)
	AuthzFinal.Expires = &exp
	AuthzFinal.Challenges[0].Status = "valid"

	return va, ssa, &ra, fc, cleanUp
}

func assertAuthzEqual(t *testing.T, a1, a2 core.Authorization) {
	test.Assert(t, a1.ID == a2.ID, "ret != DB: ID")
	test.Assert(t, a1.Identifier == a2.Identifier, "ret != DB: Identifier")
	test.Assert(t, a1.Status == a2.Status, "ret != DB: Status")
	test.Assert(t, a1.RegistrationID == a2.RegistrationID, "ret != DB: RegID")
	if a1.Expires == nil && a2.Expires == nil {
		return
	} else if a1.Expires == nil || a2.Expires == nil {
		t.Errorf("one and only one of authorization's Expires was nil; ret %v, DB %v", a1, a2)
	} else {
		test.Assert(t, a1.Expires.Equal(*a2.Expires), "ret != DB: Expires")
	}

	// Not testing: Challenges
}

func TestValidateContacts(t *testing.T) {
	tel, _ := core.ParseAcmeURL("tel:")
	ansible, _ := core.ParseAcmeURL("ansible:earth.sol.milkyway.laniakea/letsencrypt")
	validEmail, _ := core.ParseAcmeURL("mailto:admin@email.com")
	invalidEmail, _ := core.ParseAcmeURL("mailto:admin@example.com")
	malformedEmail, _ := core.ParseAcmeURL("mailto:admin.com")

	nStats, _ := statsd.NewNoopClient()

	err := validateContacts([]*core.AcmeURL{}, &mocks.MockDNS{}, nStats)
	test.AssertNotError(t, err, "No Contacts")

	err = validateContacts([]*core.AcmeURL{tel}, &mocks.MockDNS{}, nStats)
	test.AssertNotError(t, err, "Simple Telephone")

	err = validateContacts([]*core.AcmeURL{validEmail}, &mocks.MockDNS{}, nStats)
	test.AssertNotError(t, err, "Valid Email")

	err = validateContacts([]*core.AcmeURL{invalidEmail}, &mocks.MockDNS{}, nStats)
	test.AssertError(t, err, "Invalid Email")

	err = validateContacts([]*core.AcmeURL{malformedEmail}, &mocks.MockDNS{}, nStats)
	test.AssertError(t, err, "Malformed Email")

	err = validateContacts([]*core.AcmeURL{ansible}, &mocks.MockDNS{}, nStats)
	test.AssertError(t, err, "Unknown scehme")
}

func TestValidateEmail(t *testing.T) {
	_, err := validateEmail("an email`", &mocks.MockDNS{})
	test.AssertError(t, err, "Malformed")

	_, err = validateEmail("a@not.a.domain", &mocks.MockDNS{})
	test.AssertError(t, err, "Cannot resolve")
	t.Logf("No Resolve: %s", err)

	_, err = validateEmail("a@example.com", &mocks.MockDNS{})
	test.AssertError(t, err, "No MX Record")
	t.Logf("No MX: %s", err)

	_, err = validateEmail("a@email.com", &mocks.MockDNS{})
	test.AssertNotError(t, err, "Valid")
}

func TestNewRegistration(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	mailto, _ := core.ParseAcmeURL("mailto:foo@letsencrypt.org")
	input := core.Registration{
		Contact: []*core.AcmeURL{mailto},
		Key:     AccountKeyB,
	}

	result, err := ra.NewRegistration(input)
	if err != nil {
		t.Fatalf("could not create new registration: %s", err)
	}

	test.Assert(t, core.KeyDigestEquals(result.Key, AccountKeyB), "Key didn't match")
	test.Assert(t, len(result.Contact) == 1, "Wrong number of contacts")
	test.Assert(t, mailto.String() == result.Contact[0].String(),
		"Contact didn't match")
	test.Assert(t, result.Agreement == "", "Agreement didn't default empty")

	reg, err := sa.GetRegistration(result.ID)
	test.AssertNotError(t, err, "Failed to retrieve registration")
	test.Assert(t, core.KeyDigestEquals(reg.Key, AccountKeyB), "Retrieved registration differed.")
}

func TestNewRegistrationNoFieldOverwrite(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	mailto, _ := core.ParseAcmeURL("mailto:foo@letsencrypt.org")
	input := core.Registration{
		ID:        23,
		Key:       AccountKeyC,
		Contact:   []*core.AcmeURL{mailto},
		Agreement: "I agreed",
	}

	result, err := ra.NewRegistration(input)
	test.AssertNotError(t, err, "Could not create new registration")

	test.Assert(t, result.ID != 23, "ID shouldn't be set by user")
	// TODO: Enable this test case once we validate terms agreement.
	//test.Assert(t, result.Agreement != "I agreed", "Agreement shouldn't be set with invalid URL")

	id := result.ID
	result2, err := ra.UpdateRegistration(result, core.Registration{
		ID:  33,
		Key: ShortKey,
	})
	test.AssertNotError(t, err, "Could not update registration")
	test.Assert(t, result2.ID != 33, fmt.Sprintf("ID shouldn't be overwritten. expected %d, got %d", id, result2.ID))
	test.Assert(t, !core.KeyDigestEquals(result2.Key, ShortKey), "Key shouldn't be overwritten")
}

func TestNewRegistrationBadKey(t *testing.T) {
	_, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	mailto, _ := core.ParseAcmeURL("mailto:foo@letsencrypt.org")
	input := core.Registration{
		Contact: []*core.AcmeURL{mailto},
		Key:     ShortKey,
	}

	_, err := ra.NewRegistration(input)
	test.AssertError(t, err, "Should have rejected authorization with short key")
}

func TestNewAuthorization(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	_, err := ra.NewAuthorization(AuthzRequest, 0)
	test.AssertError(t, err, "Authorization cannot have registrationID == 0")

	authz, err := ra.NewAuthorization(AuthzRequest, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization failed")

	// Verify that returned authz same as DB
	dbAuthz, err := sa.GetAuthorization(authz.ID)
	test.AssertNotError(t, err, "Could not fetch authorization from database")
	assertAuthzEqual(t, authz, dbAuthz)

	// Verify that the returned authz has the right information
	test.Assert(t, authz.RegistrationID == Registration.ID, "Initial authz did not get the right registration ID")
	test.Assert(t, authz.Identifier == AuthzRequest.Identifier, "Initial authz had wrong identifier")
	test.Assert(t, authz.Status == core.StatusPending, "Initial authz not pending")

	// TODO Verify that challenges are correct
	test.Assert(t, len(authz.Challenges) == 2, "Incorrect number of challenges returned")
	test.Assert(t, authz.Challenges[0].Type == core.ChallengeTypeSimpleHTTP, "Challenge 0 not SimpleHTTP")
	test.Assert(t, authz.Challenges[1].Type == core.ChallengeTypeDVSNI, "Challenge 1 not DVSNI")
	test.Assert(t, authz.Challenges[0].IsSane(false), "Challenge 0 is not sane")
	test.Assert(t, authz.Challenges[1].IsSane(false), "Challenge 1 is not sane")

	t.Log("DONE TestNewAuthorization")
}

func TestUpdateAuthorization(t *testing.T) {
	va, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// We know this is OK because of TestNewAuthorization
	authz, err := ra.NewAuthorization(AuthzRequest, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization failed")

	authz, err = ra.UpdateAuthorization(authz, ResponseIndex, Response)
	test.AssertNotError(t, err, "UpdateAuthorization failed")

	// Verify that returned authz same as DB
	dbAuthz, err := sa.GetAuthorization(authz.ID)
	test.AssertNotError(t, err, "Could not fetch authorization from database")
	assertAuthzEqual(t, authz, dbAuthz)

	// Verify that the VA got the authz, and it's the same as the others
	test.Assert(t, va.Called, "Authorization was not passed to the VA")
	assertAuthzEqual(t, authz, va.Argument)

	// Verify that the responses are reflected
	test.Assert(t, len(va.Argument.Challenges) > 0, "Authz passed to VA has no challenges")

	t.Log("DONE TestUpdateAuthorization")
}

func TestUpdateAuthorizationReject(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	// We know this is OK because of TestNewAuthorization
	authz, err := ra.NewAuthorization(AuthzRequest, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization failed")

	// Change the account key
	reg, err := sa.GetRegistration(authz.RegistrationID)
	test.AssertNotError(t, err, "GetRegistration failed")
	reg.Key = AccountKeyC // was AccountKeyA
	err = sa.UpdateRegistration(reg)
	test.AssertNotError(t, err, "UpdateRegistration failed")

	// Verify that the RA rejected the authorization request
	_, err = ra.UpdateAuthorization(authz, ResponseIndex, Response)
	test.AssertEquals(t, err, core.UnauthorizedError("Challenge cannot be updated with a different key"))

	t.Log("DONE TestUpdateAuthorizationReject")
}

func TestOnValidationUpdateSuccess(t *testing.T) {
	_, sa, ra, fclk, cleanUp := initAuthorities(t)
	defer cleanUp()
	authzUpdated, _ := sa.NewPendingAuthorization(AuthzInitial)
	expires := fclk.Now().Add(300 * 24 * time.Hour)
	authzUpdated.Expires = &expires
	sa.UpdatePendingAuthorization(authzUpdated)

	// Simulate a successful simpleHTTP challenge
	authzFromVA := authzUpdated
	authzFromVA.Challenges[0].Status = core.StatusValid

	ra.OnValidationUpdate(authzFromVA)

	// Verify that the Authz in the DB is the same except for Status->StatusValid
	authzFromVA.Status = core.StatusValid
	dbAuthz, err := sa.GetAuthorization(authzFromVA.ID)
	test.AssertNotError(t, err, "Could not fetch authorization from database")
	t.Log("authz from VA: ", authzFromVA)
	t.Log("authz from DB: ", dbAuthz)

	assertAuthzEqual(t, authzFromVA, dbAuthz)
}

func TestOnValidationUpdateFailure(t *testing.T) {
	_, sa, ra, fclk, cleanUp := initAuthorities(t)
	defer cleanUp()
	authzFromVA, _ := sa.NewPendingAuthorization(AuthzInitial)
	expires := fclk.Now().Add(300 * 24 * time.Hour)
	authzFromVA.Expires = &expires
	sa.UpdatePendingAuthorization(authzFromVA)
	authzFromVA.Challenges[0].Status = core.StatusInvalid

	err := ra.OnValidationUpdate(authzFromVA)
	test.AssertNotError(t, err, "unable to update validation")

	authzFromVA.Status = core.StatusInvalid
	dbAuthz, err := sa.GetAuthorization(authzFromVA.ID)
	test.AssertNotError(t, err, "Could not fetch authorization from database")
	assertAuthzEqual(t, authzFromVA, dbAuthz)
}

func TestCertificateKeyNotEqualAccountKey(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	authz := core.Authorization{}
	authz, _ = sa.NewPendingAuthorization(authz)
	authz.Identifier = core.AcmeIdentifier{
		Type:  core.IdentifierDNS,
		Value: "www.example.com",
	}
	csr := x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKey:          AccountKeyA.Key,
		DNSNames:           []string{"www.example.com"},
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csr, AccountPrivateKey.Key)
	test.AssertNotError(t, err, "Failed to sign CSR")
	parsedCSR, err := x509.ParseCertificateRequest(csrBytes)
	test.AssertNotError(t, err, "Failed to parse CSR")
	sa.UpdatePendingAuthorization(authz)
	sa.FinalizeAuthorization(authz)
	certRequest := core.CertificateRequest{
		CSR: parsedCSR,
	}

	// Registration has key == AccountKeyA
	_, err = ra.NewCertificate(certRequest, Registration.ID)
	test.AssertError(t, err, "Should have rejected cert with key = account key")
	test.AssertEquals(t, err.Error(), "Certificate public key must be different than account key")

	t.Log("DONE TestCertificateKeyNotEqualAccountKey")
}

func TestAuthorizationRequired(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	AuthzFinal.RegistrationID = 1
	AuthzFinal, _ = sa.NewPendingAuthorization(AuthzFinal)
	sa.UpdatePendingAuthorization(AuthzFinal)
	sa.FinalizeAuthorization(AuthzFinal)

	// ExampleCSR requests not-example.com and www.not-example.com,
	// but the authorization only covers not-example.com
	certRequest := core.CertificateRequest{
		CSR: ExampleCSR,
	}

	_, err := ra.NewCertificate(certRequest, 1)
	test.Assert(t, err != nil, "Issued certificate with insufficient authorization")

	t.Log("DONE TestAuthorizationRequired")
}

func TestNewCertificate(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	AuthzFinal.RegistrationID = Registration.ID
	AuthzFinal, _ = sa.NewPendingAuthorization(AuthzFinal)
	sa.UpdatePendingAuthorization(AuthzFinal)
	sa.FinalizeAuthorization(AuthzFinal)

	// Inject another final authorization to cover www.example.com
	authzFinalWWW := AuthzFinal
	authzFinalWWW.Identifier.Value = "www.not-example.com"
	authzFinalWWW, _ = sa.NewPendingAuthorization(authzFinalWWW)
	sa.FinalizeAuthorization(authzFinalWWW)

	certRequest := core.CertificateRequest{
		CSR: ExampleCSR,
	}

	cert, err := ra.NewCertificate(certRequest, Registration.ID)
	test.AssertNotError(t, err, "Failed to issue certificate")
	if err != nil {
		return
	}

	parsedCert, err := x509.ParseCertificate(cert.DER)
	test.AssertNotError(t, err, "Failed to parse certificate")
	if err != nil {
		return
	}

	// Verify that cert shows up and is as expected
	dbCert, err := sa.GetCertificate(core.SerialToString(parsedCert.SerialNumber))
	test.AssertNotError(t, err, fmt.Sprintf("Could not fetch certificate %032x from database",
		parsedCert.SerialNumber))
	if err != nil {
		return
	}
	test.Assert(t, bytes.Compare(cert.DER, dbCert.DER) == 0, "Certificates differ")

	t.Log("DONE TestOnValidationUpdate")
}

func TestTotalCertRateLimit(t *testing.T) {
	_, sa, ra, fc, cleanUp := initAuthorities(t)
	defer cleanUp()

	ra.rlPolicies = cmd.RateLimitConfig{
		TotalCertificates: cmd.RateLimitPolicy{
			Threshold: 1,
			Window:    cmd.ConfigDuration{Duration: 24 * 90 * time.Hour},
		},
	}
	fc.Add(24 * 90 * time.Hour)

	AuthzFinal.RegistrationID = Registration.ID
	AuthzFinal, _ = sa.NewPendingAuthorization(AuthzFinal)
	sa.UpdatePendingAuthorization(AuthzFinal)
	sa.FinalizeAuthorization(AuthzFinal)

	// Inject another final authorization to cover www.example.com
	authzFinalWWW := AuthzFinal
	authzFinalWWW.Identifier.Value = "www.not-example.com"
	authzFinalWWW, _ = sa.NewPendingAuthorization(authzFinalWWW)
	sa.FinalizeAuthorization(authzFinalWWW)

	certRequest := core.CertificateRequest{
		CSR: ExampleCSR,
	}

	_, err := ra.NewCertificate(certRequest, Registration.ID)
	test.AssertNotError(t, err, "Failed to issue certificate")

	fc.Add(time.Hour)

	_, err = ra.NewCertificate(certRequest, Registration.ID)
	test.AssertError(t, err, "Total certificate rate limit failed")
}

func TestDomainsForRateLimiting(t *testing.T) {
	domains, err := domainsForRateLimiting([]string{})
	test.AssertNotError(t, err, "failed on empty")
	test.AssertEquals(t, len(domains), 0)

	domains, err = domainsForRateLimiting([]string{"www.example.com", "example.com"})
	test.AssertNotError(t, err, "failed on example.com")
	test.AssertEquals(t, len(domains), 1)
	test.AssertEquals(t, domains[0], "example.com")

	domains, err = domainsForRateLimiting([]string{"www.example.com", "example.com", "www.example.co.uk"})
	test.AssertNotError(t, err, "failed on example.co.uk")
	test.AssertEquals(t, len(domains), 2)
	test.AssertEquals(t, domains[0], "example.com")
	test.AssertEquals(t, domains[1], "example.co.uk")

	domains, err = domainsForRateLimiting([]string{"www.example.com", "example.com", "www.example.co.uk", "co.uk"})
	test.AssertError(t, err, "should fail on public suffix")

	domains, err = domainsForRateLimiting([]string{"foo.bar.baz.www.example.com", "baz.example.com"})
	test.AssertNotError(t, err, "failed on foo.bar.baz")
	test.AssertEquals(t, len(domains), 1)
	test.AssertEquals(t, domains[0], "example.com")
}

type mockSAWithNameCounts struct {
	mocks.MockSA
	nameCounts map[string]int
	t          *testing.T
	clk        clock.FakeClock
}

func (m mockSAWithNameCounts) CountCertificatesByNames(names []string, earliest, latest time.Time) (ret map[string]int, err error) {
	if latest != m.clk.Now() {
		m.t.Error("incorrect latest")
	}
	if earliest != m.clk.Now().Add(-23*time.Hour) {
		m.t.Errorf("incorrect earliest")
	}
	return m.nameCounts, nil
}

func TestCheckCertificatesPerNameLimit(t *testing.T) {
	_, _, ra, fc, cleanUp := initAuthorities(t)
	defer cleanUp()

	rlp := cmd.RateLimitPolicy{
		Threshold: 3,
		Window:    cmd.ConfigDuration{Duration: 23 * time.Hour},
		Overrides: map[string]int64{
			"bigissuer.com":     100,
			"smallissuer.co.uk": 1,
		},
	}

	mockSA := &mockSAWithNameCounts{
		nameCounts: map[string]int{
			"example.com": 1,
		},
		clk: fc,
		t:   t,
	}

	ra.SA = mockSA

	// One base domain, below threshold
	err := ra.checkCertificatesPerNameLimit([]string{"www.example.com", "example.com"}, rlp)
	test.AssertNotError(t, err, "rate limited example.com incorrectly")

	// One base domain, above threshold
	mockSA.nameCounts["example.com"] = 10
	err = ra.checkCertificatesPerNameLimit([]string{"www.example.com", "example.com"}, rlp)
	test.AssertError(t, err, "incorrectly failed to rate limit example.com")
	if _, ok := err.(core.RateLimitedError); !ok {
		t.Errorf("Incorrect error type %#v", err)
	}

	// SA misbehaved and didn't send back a count for every input name
	err = ra.checkCertificatesPerNameLimit([]string{"zombo.com", "www.example.com", "example.com"}, rlp)
	test.AssertError(t, err, "incorrectly failed to error on misbehaving SA")

	// Two base domains, one above threshold but with an override.
	mockSA.nameCounts["example.com"] = 0
	mockSA.nameCounts["bigissuer.com"] = 50
	err = ra.checkCertificatesPerNameLimit([]string{"www.example.com", "subdomain.bigissuer.com"}, rlp)
	test.AssertNotError(t, err, "incorrectly rate limited bigissuer")

	// Two base domains, one above its override
	mockSA.nameCounts["example.com"] = 0
	mockSA.nameCounts["bigissuer.com"] = 100
	err = ra.checkCertificatesPerNameLimit([]string{"www.example.com", "subdomain.bigissuer.com"}, rlp)
	test.AssertError(t, err, "incorrectly failed to rate limit bigissuer")
	if _, ok := err.(core.RateLimitedError); !ok {
		t.Errorf("Incorrect error type")
	}

	// One base domain, above its override (which is below threshold)
	mockSA.nameCounts["smallissuer.co.uk"] = 1
	err = ra.checkCertificatesPerNameLimit([]string{"www.smallissuer.co.uk"}, rlp)
	test.AssertError(t, err, "incorrectly failed to rate limit smallissuer")
	if _, ok := err.(core.RateLimitedError); !ok {
		t.Errorf("Incorrect error type %#v", err)
	}
}

var CAkeyPEM = "-----BEGIN RSA PRIVATE KEY-----\n" +
	"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\n" +
	"-----END RSA PRIVATE KEY-----"

var CAcertPEM = "-----BEGIN CERTIFICATE-----\n" +
	"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\n" +
	"-----END CERTIFICATE-----"

// CSR generated by Go:
// * Random public key
// * CN = not-example.com
// * DNSNames = not-example.com, www.not-example.com
var CSRhex = "308202ae308201960201003027310b300906035504061302" +
	"5553311830160603550403130f6e6f742d6578616d706c65" +
	"2e636f6d30820122300d06092a864886f70d010101050003" +
	"82010f003082010a0282010100a4f507b52ca2766e2cea7b" +
	"aaada9c3e08ea3423d6617ae84df65b6ed7e6c031605851b" +
	"f0a14f3461a9f1882de9808b8e59d639c85eec58dbe653e3" +
	"855e94d81904b7ce6675a1930e0ea6537aa3936fdc9d9780" +
	"bc9596e5ec183811b137f83f28781d619fae8471ff3db1ad" +
	"5a4b5cbf96d127d0f16e3c6ccbb97c48b43a7ddfcc17fdf3" +
	"eac049cc81e4703ba90ce15d3cdfd9d0a3b0ec138f1c06e0" +
	"8212c94e6884480d4b8f16fcf38f1b10d942cfca558b322e" +
	"d8896be3104fb40e6851f3b414929b4f54fae89668ab0cbf" +
	"76b7eb94703b17a73c9189409b088e7d61f39560a413562e" +
	"64f26b650aede2d27bd2bacfc55d6a106243ba6ce07046d4" +
	"fda618881b0203010001a042304006092a864886f70d0109" +
	"0e31333031302f0603551d1104283026820f6e6f742d6578" +
	"616d706c652e636f6d82137777772e6e6f742d6578616d70" +
	"6c652e636f6d300d06092a864886f70d01010b0500038201" +
	"01006e168e521ea37595698ceab29a3815c57b301dcd9c86" +
	"6fdc7cfb966afde87da52c699f43133a6abfbbeb031f1b02" +
	"cb072c8543b73fdffff6ee002ed367fe3b09992ac496c4ef" +
	"1b7487e68c25f66b8d1223a07feebfad8fd7f19727bff7b4" +
	"02bf6bef705c0a48e800e15bafbc622cb62ee446814234a3" +
	"ebf9b8ba3c094d64b64aaa1b2b955f769ce60e9e304f7781" +
	"57814f2f1cb1c4e2ee58bcdc0640dd2f0ff387ddb61ed479" +
	"7ea935e79638a63dd64bd36723f34c1e6725ae57d8ff63f8" +
	"749ac154cfaa55b3d3cccd7d42994c922cbb171a43c7ab68" +
	"5170d833829d28a574fb25ffcf0fd5d3f19becaef2223541" +
	"c2a8e596a80c8cde27bc78e20d7171fe43d8"
