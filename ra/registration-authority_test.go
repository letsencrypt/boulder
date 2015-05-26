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

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/signer/local"
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/mattn/go-sqlite3"
	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/square/go-jose"
	"github.com/letsencrypt/boulder/ca"
	"github.com/letsencrypt/boulder/core"
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

type MockCADatabase struct {
	// empty
}

func NewMockCertificateAuthorityDatabase() (core.CertificateAuthorityDatabase, error) {
	return &MockCADatabase{}, nil
}

func (cadb *MockCADatabase) Begin() error {
	return nil
}

func (cadb *MockCADatabase) Commit() error {
	return nil
}

func (cadb *MockCADatabase) Rollback() error {
	return nil
}

func (cadb *MockCADatabase) IncrementAndGetSerial() (int, error) {
	return 1, nil
}

var (
	// These values we simulate from the client
	AccountKeyJSON = []byte(`{
		"kty":"RSA",
		"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":"AQAB"
	}`)
	AccountKey = jose.JsonWebKey{}

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

	AuthzRequest = core.Authorization{
		Identifier: core.AcmeIdentifier{
			Type:  core.IdentifierDNS,
			Value: "not-example.com",
		},
	}

	ResponseIndex = 0
	Response      = core.Challenge{
		Path: "Hf5GrX4Q7EBax9hc2jJnfw",
	}

	ExampleCSR = &x509.CertificateRequest{}

	// These values are populated by the tests as we go
	AuthzInitial  = core.Authorization{}
	AuthzUpdated  = core.Authorization{}
	AuthzFromVA   = core.Authorization{}
	AuthzFinal    = core.Authorization{}
	AuthzFinalWWW = core.Authorization{}
)

func initAuthorities(t *testing.T) (core.CertificateAuthority, *DummyValidationAuthority, *sa.SQLStorageAuthority, core.RegistrationAuthority) {
	err := json.Unmarshal(AccountKeyJSON, &AccountKey)
	test.AssertNotError(t, err, "Failed to unmarshal public JWK")

	err = json.Unmarshal(AccountPrivateKeyJSON, &AccountPrivateKey)
	test.AssertNotError(t, err, "Failed to unmarshal private JWK")

	sa, err := sa.NewSQLStorageAuthority("sqlite3", ":memory:")
	test.AssertNotError(t, err, "Failed to create SA")
	sa.InitTables()

	va := &DummyValidationAuthority{}

	// PEM files in certificate-authority_test.go
	caKeyPEM, _ := pem.Decode([]byte(CA_KEY_PEM))
	caKey, _ := x509.ParsePKCS1PrivateKey(caKeyPEM.Bytes)
	caCertPEM, _ := pem.Decode([]byte(CA_CERT_PEM))
	caCert, _ := x509.ParseCertificate(caCertPEM.Bytes)
	signer, _ := local.NewSigner(caKey, caCert, x509.SHA256WithRSA, nil)
	pa := policy.NewPolicyAuthorityImpl()
	cadb := &MockCADatabase{}
	ca := ca.CertificateAuthorityImpl{Signer: signer, SA: sa, PA: pa, DB: cadb, ValidityPeriod: time.Hour * 8760, NotAfter: time.Now().Add(time.Hour * 8761)}
	csrDER, _ := hex.DecodeString(CSR_HEX)
	ExampleCSR, _ = x509.ParseCertificateRequest(csrDER)

	// This registration implicitly gets ID = 1
	sa.NewRegistration(core.Registration{Key: AccountKey})

	ra := NewRegistrationAuthorityImpl()
	ra.SA = sa
	ra.VA = va
	ra.CA = &ca
	ra.PA = pa

	return &ca, va, sa, &ra
}

func assertAuthzEqual(t *testing.T, a1, a2 core.Authorization) {
	test.Assert(t, a1.ID == a2.ID, "ret != DB: ID")
	test.Assert(t, a1.Identifier == a2.Identifier, "ret != DB: Identifier")
	test.Assert(t, a1.Status == a2.Status, "ret != DB: Status")
	test.Assert(t, a1.RegistrationID == a2.RegistrationID, "ret != DB: RegID")
	// Not testing: Contact, Challenges
}

func TestNewAuthorization(t *testing.T) {
	_, _, sa, ra := initAuthorities(t)

	_, err := ra.NewAuthorization(AuthzRequest, 0)
	test.AssertError(t, err, "Authorization cannot have registrationID == 0")

	authz, err := ra.NewAuthorization(AuthzRequest, 1)
	test.AssertNotError(t, err, "NewAuthorization failed")

	// Verify that returned authz same as DB
	dbAuthz, err := sa.GetAuthorization(authz.ID)
	test.AssertNotError(t, err, "Could not fetch authorization from database")
	assertAuthzEqual(t, authz, dbAuthz)

	// Verify that the returned authz has the right information
	test.Assert(t, authz.RegistrationID == 1, "Initial authz did not get the right registration ID")
	test.Assert(t, authz.Identifier == AuthzRequest.Identifier, "Initial authz had wrong identifier")
	test.Assert(t, authz.Status == core.StatusPending, "Initial authz not pending")

	// TODO Verify challenges
	test.Assert(t, len(authz.Challenges) == 2, "Incorrect number of challenges returned")
	test.Assert(t, authz.Challenges[0].Type == core.ChallengeTypeSimpleHTTPS, "Challenge 0 not SimpleHTTPS")
	test.Assert(t, authz.Challenges[1].Type == core.ChallengeTypeDVSNI, "Challenge 1 not DVSNI")

	// If we get to here, we'll use this authorization for the next test
	AuthzInitial = authz

	// TODO Test failure cases
	t.Log("DONE TestNewAuthorization")
}

func TestUpdateAuthorization(t *testing.T) {
	_, va, sa, ra := initAuthorities(t)
	AuthzInitial.ID, _ = sa.NewPendingAuthorization()
	sa.UpdatePendingAuthorization(AuthzInitial)

	authz, err := ra.UpdateAuthorization(AuthzInitial, ResponseIndex, Response)
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
	simpleHttps := va.Argument.Challenges[0]
	test.Assert(t, simpleHttps.Path == Response.Path, "simpleHttps changed")

	// If we get to here, we'll use this authorization for the next test
	AuthzUpdated = authz

	// TODO Test failure cases
	t.Log("DONE TestUpdateAuthorization")
}

func TestOnValidationUpdate(t *testing.T) {
	_, _, sa, ra := initAuthorities(t)
	AuthzUpdated.ID, _ = sa.NewPendingAuthorization()
	sa.UpdatePendingAuthorization(AuthzUpdated)

	// Simulate a successful simpleHTTPS challenge
	AuthzFromVA = AuthzUpdated
	AuthzFromVA.Challenges[0].Status = core.StatusValid

	ra.OnValidationUpdate(AuthzFromVA)

	// Verify that the Authz in the DB is the same except for Status->StatusValid
	AuthzFromVA.Status = core.StatusValid
	dbAuthz, err := sa.GetAuthorization(AuthzFromVA.ID)
	test.AssertNotError(t, err, "Could not fetch authorization from database")
	assertAuthzEqual(t, AuthzFromVA, dbAuthz)
	t.Log(" ~~> from VA: ", AuthzFromVA.Status)
	t.Log(" ~~> from DB: ", dbAuthz.Status)

	// If we get to here, we'll use this authorization for the next test
	AuthzFinal = dbAuthz

	// TODO Test failure cases
	t.Log("DONE TestOnValidationUpdate")
}

func TestCertificateKeyNotEqualAccountKey(t *testing.T) {
	_, _, sa, ra := initAuthorities(t)
	authz := core.Authorization{}
	authz.ID, _ = sa.NewPendingAuthorization()
	authz.Identifier = core.AcmeIdentifier{
		Type:  core.IdentifierDNS,
		Value: "www.example.com",
	}
	csr := x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKey:          AccountKey.Key,
		DNSNames:           []string{"www.example.com"},
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csr, AccountPrivateKey.Key)
	test.AssertNotError(t, err, "Failed to sign CSR")
	parsedCsr, err := x509.ParseCertificateRequest(csrBytes)
	test.AssertNotError(t, err, "Failed to parse CSR")
	sa.UpdatePendingAuthorization(authz)
	sa.FinalizeAuthorization(authz)
	authzURL, _ := url.Parse("http://doesnt.matter/" + authz.ID)
	certRequest := core.CertificateRequest{
		CSR:            parsedCsr,
		Authorizations: []core.AcmeURL{core.AcmeURL(*authzURL)},
	}

	// Registration id 1 has key == AccountKey
	_, err = ra.NewCertificate(certRequest, 1)
	test.AssertError(t, err, "Should have rejected cert with key = account key")
	test.AssertEquals(t, err.Error(), "Certificate public key must be different than account key")
}

func TestNewCertificate(t *testing.T) {
	_, _, sa, ra := initAuthorities(t)
	AuthzFinal.RegistrationID = 1
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

	certRequest := core.CertificateRequest{
		CSR:            ExampleCSR,
		Authorizations: []core.AcmeURL{core.AcmeURL(*url1), core.AcmeURL(*url2)},
	}

	cert, err := ra.NewCertificate(certRequest, 1)
	test.AssertNotError(t, err, "Failed to issue certificate")
	parsedCert, err := x509.ParseCertificate(cert.DER)
	test.AssertNotError(t, err, "Failed to parse certificate")

	// Verify that cert shows up and is as expected
	dbCert, err := sa.GetCertificate(core.SerialToString(parsedCert.SerialNumber))
	test.AssertNotError(t, err, fmt.Sprintf("Could not fetch certificate %032x from database",
		parsedCert.SerialNumber))
	test.Assert(t, bytes.Compare(cert.DER, dbCert) == 0, "Certificates differ")

	// TODO Test failure cases
	t.Log("DONE TestOnValidationUpdate")
}

var CA_KEY_PEM = "-----BEGIN RSA PRIVATE KEY-----\n" +
	"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\n" +
	"-----END RSA PRIVATE KEY-----"

var CA_CERT_PEM = "-----BEGIN CERTIFICATE-----\n" +
	"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\n" +
	"-----END CERTIFICATE-----"

// CSR generated by Go:
// * Random public key
// * CN = not-example.com
// * DNSNames = not-example.com
var CSR_HEX = "3082028c30820174020100301a311830160603550403130f" +
	"6e6f742d6578616d706c652e636f6d30820122300d06092a" +
	"864886f70d01010105000382010f003082010a0282010100" +
	"aac67dd1e11fae980048b0ac91be005f21d9df8bb38461cc" +
	"a7dfad601a00e91ae488c240a03ec53a5752a33d837d2d9c" +
	"357c6a99ea7e55fe75482524480bb367aa85f75541bd0284" +
	"ede1ab9b54925a5c9f88d08f9dc857ee707a59d3503b31ea" +
	"64e42099acd70d2204c872ef49983e44cc2bc24389159fc5" +
	"f6ca41b80540fb7a2fbf8aa43af7f539782f20f185d416cc" +
	"66a88e5f8913a292b4a217e5b12e8244a9686af3b49ac88b" +
	"215c6eb097c4befa3e66257a1358791e2bc471c18ba2ca6e" +
	"161d2dcb53ebcb06e6b4b2e6cd42ff970581bc4971009cbd" +
	"7ccc3f89648db720e2908a1be613a9c3afb46b477261c1bc" +
	"c057bc749a102e6bd9dc45d87b2d97c50203010001a02d30" +
	"2b06092a864886f70d01090e311e301c301a0603551d1104" +
	"133011820f6e6f742d6578616d706c652e636f6d300d0609" +
	"2a864886f70d01010b05000382010100a37025c2cb88b4fa" +
	"f3c8417820a78a069b92cef45a3d2f3fbd18f41a07128258" +
	"38bc55e6c1c416e5f34c365924391294741c23657ffa77e4" +
	"aa3d589b560cbb9156aae175637cbb5061d69eefa7f432ca" +
	"c9e4d03feaa367954cf6986a72ca76307c01852db72b43ae" +
	"5ab7f673b81b58e06d8af1f681cd7c88d2fbc8c80d592a3f" +
	"7c3ea20035b73c8e6afc8daea4d168fe469f7da9e4bac660" +
	"fc207d1d93dce118dc7381e69fa4af37bb4d4d6d5342fa55" +
	"7798a363aa04cf350ad1748e96eabee04fa379dd98524ea1" +
	"53f07e1654e6077f4aaaf5c5b27edaf0385b48e0fc281424" +
	"6363a01370c89e666169276eb133731cff2379d46d2fff9d" +
	"f277b6d23fa24f9b"
