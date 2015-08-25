// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
)

const dbConnStr = "mysql+tcp://boulder@localhost:3306/boulder_sa_test"

var log = mocks.UseMockLog()

// initSA constructs a SQLStorageAuthority and a clean up function
// that should be defer'ed to the end of the test.
func initSA(t *testing.T) (*SQLStorageAuthority, func()) {
	dbMap, err := NewDbMap(dbConnStr)
	if err != nil {
		t.Fatalf("Failed to create dbMap: %s", err)
	}

	sa, err := NewSQLStorageAuthority(dbMap)
	if err != nil {
		t.Fatalf("Failed to create SA: %s", err)
	}
	cleanUp := test.ResetTestDatabase(t, dbMap.Db)
	return sa, cleanUp
}

var (
	anotherKey = `{
	"kty":"RSA",
	"n": "vd7rZIoTLEe-z1_8G1FcXSw9CQFEJgV4g9V277sER7yx5Qjz_Pkf2YVth6wwwFJEmzc0hoKY-MMYFNwBE4hQHw",
	"e":"AQAB"
}`
)

func TestAddRegistration(t *testing.T) {
	sa, cleanUp := initSA(t)
	defer cleanUp()

	jwk := satest.GoodJWK()

	contact, err := core.ParseAcmeURL("mailto:foo@example.com")
	if err != nil {
		t.Fatalf("unable to parse contact link: %s", err)
	}
	contacts := []*core.AcmeURL{contact}
	reg, err := sa.NewRegistration(core.Registration{
		Key:     jwk,
		Contact: contacts,
	})
	if err != nil {
		t.Fatalf("Couldn't create new registration: %s", err)
	}
	test.Assert(t, reg.ID != 0, "ID shouldn't be 0")
	test.AssertDeepEquals(t, reg.Contact, contacts)

	_, err = sa.GetRegistration(0)
	test.AssertError(t, err, "Registration object for ID 0 was returned")

	dbReg, err := sa.GetRegistration(reg.ID)
	test.AssertNotError(t, err, fmt.Sprintf("Couldn't get registration with ID %v", reg.ID))

	expectedReg := core.Registration{
		ID:  reg.ID,
		Key: jwk,
	}
	test.AssertEquals(t, dbReg.ID, expectedReg.ID)
	test.Assert(t, core.KeyDigestEquals(dbReg.Key, expectedReg.Key), "Stored key != expected")

	u, _ := core.ParseAcmeURL("test.com")

	newReg := core.Registration{ID: reg.ID, Key: jwk, Contact: []*core.AcmeURL{u}, Agreement: "yes"}
	err = sa.UpdateRegistration(newReg)
	test.AssertNotError(t, err, fmt.Sprintf("Couldn't get registration with ID %v", reg.ID))
	dbReg, err = sa.GetRegistrationByKey(jwk)
	test.AssertNotError(t, err, "Couldn't get registration by key")

	test.AssertEquals(t, dbReg.ID, newReg.ID)
	test.AssertEquals(t, dbReg.Agreement, newReg.Agreement)

	var anotherJWK jose.JsonWebKey
	err = json.Unmarshal([]byte(anotherKey), &anotherJWK)
	test.AssertNotError(t, err, "couldn't unmarshal anotherJWK")
	_, err = sa.GetRegistrationByKey(anotherJWK)
	test.AssertError(t, err, "Registration object for invalid key was returned")
}

func TestNoSuchRegistrationErrors(t *testing.T) {
	sa, cleanUp := initSA(t)
	defer cleanUp()

	_, err := sa.GetRegistration(100)
	if _, ok := err.(NoSuchRegistrationError); !ok {
		t.Errorf("GetRegistration: expected NoSuchRegistrationError, got %T type error (%s)", err, err)
	}

	jwk := satest.GoodJWK()
	_, err = sa.GetRegistrationByKey(jwk)
	if _, ok := err.(NoSuchRegistrationError); !ok {
		t.Errorf("GetRegistrationByKey: expected a NoSuchRegistrationError, got %T type error (%s)", err, err)
	}

	err = sa.UpdateRegistration(core.Registration{ID: 100, Key: jwk})
	if _, ok := err.(NoSuchRegistrationError); !ok {
		t.Errorf("UpdateRegistration: expected a NoSuchRegistrationError, got %T type error (%v)", err, err)
	}
}

func TestAddAuthorization(t *testing.T) {
	sa, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	PA := core.Authorization{RegistrationID: reg.ID}

	PA, err := sa.NewPendingAuthorization(PA)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	test.Assert(t, PA.ID != "", "ID shouldn't be blank")

	dbPa, err := sa.GetAuthorization(PA.ID)
	test.AssertNotError(t, err, "Couldn't get pending authorization with ID "+PA.ID)
	test.AssertMarshaledEquals(t, PA, dbPa)

	expectedPa := core.Authorization{ID: PA.ID}
	test.AssertMarshaledEquals(t, dbPa.ID, expectedPa.ID)

	combos := make([][]int, 1)
	combos[0] = []int{0, 1}

	exp := time.Now().AddDate(0, 0, 1)
	identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "wut.com"}
	newPa := core.Authorization{ID: PA.ID, Identifier: identifier, RegistrationID: reg.ID, Status: core.StatusPending, Expires: &exp, Combinations: combos}
	err = sa.UpdatePendingAuthorization(newPa)
	test.AssertNotError(t, err, "Couldn't update pending authorization with ID "+PA.ID)

	newPa.Status = core.StatusValid
	err = sa.FinalizeAuthorization(newPa)
	test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+PA.ID)

	dbPa, err = sa.GetAuthorization(PA.ID)
	test.AssertNotError(t, err, "Couldn't get authorization with ID "+PA.ID)
}

func CreateDomainAuth(t *testing.T, domainName string, sa *SQLStorageAuthority) (authz core.Authorization) {
	return CreateDomainAuthWithRegId(t, domainName, sa, 42)
}

func CreateDomainAuthWithRegId(t *testing.T, domainName string, sa *SQLStorageAuthority, regID int64) (authz core.Authorization) {

	// create pending auth
	authz, err := sa.NewPendingAuthorization(core.Authorization{RegistrationID: regID, Challenges: []core.Challenge{core.Challenge{}}})
	if err != nil {
		t.Fatalf("Couldn't create new pending authorization: %s", err)
	}
	test.Assert(t, authz.ID != "", "ID shouldn't be blank")

	// prepare challenge for auth
	u, err := core.ParseAcmeURL(domainName)
	test.AssertNotError(t, err, "Couldn't parse domainName "+domainName)
	chall := core.Challenge{Type: "simpleHttp", Status: core.StatusValid, URI: u, Token: "THISWOULDNTBEAGOODTOKEN"}
	combos := make([][]int, 1)
	combos[0] = []int{0, 1}
	exp := time.Now().AddDate(0, 0, 1) // expire in 1 day

	// validate pending auth
	authz.Status = core.StatusPending
	authz.Identifier = core.AcmeIdentifier{Type: core.IdentifierDNS, Value: domainName}
	authz.Expires = &exp
	authz.Challenges = []core.Challenge{chall}
	authz.Combinations = combos

	// save updated auth
	err = sa.UpdatePendingAuthorization(authz)
	test.AssertNotError(t, err, "Couldn't update pending authorization with ID "+authz.ID)

	return
}

// Ensure we get only valid authorization with correct RegID
func TestGetLatestValidAuthorizationBasic(t *testing.T) {
	sa, cleanUp := initSA(t)
	defer cleanUp()

	// attempt to get unauthorized domain
	authz, err := sa.GetLatestValidAuthorization(0, core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "example.org"})
	test.AssertError(t, err, "Should not have found a valid auth for example.org")

	reg := satest.CreateWorkingRegistration(t, sa)

	// authorize "example.org"
	authz = CreateDomainAuthWithRegId(t, "example.org", sa, reg.ID)

	// finalize auth
	authz.Status = core.StatusValid
	err = sa.FinalizeAuthorization(authz)
	test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+authz.ID)

	// attempt to get authorized domain with wrong RegID
	authz, err = sa.GetLatestValidAuthorization(0, core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "example.org"})
	test.AssertError(t, err, "Should not have found a valid auth for example.org and regID 0")

	// get authorized domain
	authz, err = sa.GetLatestValidAuthorization(reg.ID, core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "example.org"})
	test.AssertNotError(t, err, "Should have found a valid auth for example.org and regID 42")
	test.AssertEquals(t, authz.Status, core.StatusValid)
	test.AssertEquals(t, authz.Identifier.Type, core.IdentifierDNS)
	test.AssertEquals(t, authz.Identifier.Value, "example.org")
	test.AssertEquals(t, authz.RegistrationID, reg.ID)
}

// Ensure we get the latest valid authorization for an ident
func TestGetLatestValidAuthorizationMultiple(t *testing.T) {
	sa, cleanUp := initSA(t)
	defer cleanUp()

	domain := "example.org"
	ident := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: domain}
	var err error

	reg := satest.CreateWorkingRegistration(t, sa)
	// create invalid authz
	authz := CreateDomainAuthWithRegId(t, domain, sa, reg.ID)
	exp := time.Now().AddDate(0, 0, 10) // expire in 10 day
	authz.Expires = &exp
	authz.Status = core.StatusInvalid
	err = sa.FinalizeAuthorization(authz)
	test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+authz.ID)

	// should not get the auth
	authz, err = sa.GetLatestValidAuthorization(reg.ID, ident)
	test.AssertError(t, err, "Should not have found a valid auth for "+domain)

	// create valid auth
	authz = CreateDomainAuthWithRegId(t, domain, sa, reg.ID)
	exp = time.Now().AddDate(0, 0, 1) // expire in 1 day
	authz.Expires = &exp
	authz.Status = core.StatusValid
	err = sa.FinalizeAuthorization(authz)
	test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+authz.ID)

	// should get the valid auth even if it's expire date is lower than the invalid one
	authz, err = sa.GetLatestValidAuthorization(reg.ID, ident)
	test.AssertNotError(t, err, "Should have found a valid auth for "+domain)
	test.AssertEquals(t, authz.Status, core.StatusValid)
	test.AssertEquals(t, authz.Identifier.Type, ident.Type)
	test.AssertEquals(t, authz.Identifier.Value, ident.Value)
	test.AssertEquals(t, authz.RegistrationID, reg.ID)

	// create a newer auth
	newAuthz := CreateDomainAuthWithRegId(t, domain, sa, reg.ID)
	exp = time.Now().AddDate(0, 0, 2) // expire in 2 day
	newAuthz.Expires = &exp
	newAuthz.Status = core.StatusValid
	err = sa.FinalizeAuthorization(newAuthz)
	test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+newAuthz.ID)

	authz, err = sa.GetLatestValidAuthorization(reg.ID, ident)
	test.AssertNotError(t, err, "Should have found a valid auth for "+domain)
	test.AssertEquals(t, authz.Status, core.StatusValid)
	test.AssertEquals(t, authz.Identifier.Type, ident.Type)
	test.AssertEquals(t, authz.Identifier.Value, ident.Value)
	test.AssertEquals(t, authz.RegistrationID, reg.ID)
	// make sure we got the latest auth
	test.AssertEquals(t, authz.ID, newAuthz.ID)
}

func TestAddCertificate(t *testing.T) {
	sa, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)

	// An example cert taken from EFF's website
	certDER, err := ioutil.ReadFile("www.eff.org.der")
	test.AssertNotError(t, err, "Couldn't read example cert DER")

	digest, err := sa.AddCertificate(certDER, reg.ID)
	test.AssertNotError(t, err, "Couldn't add www.eff.org.der")
	test.AssertEquals(t, digest, "qWoItDZmR4P9eFbeYgXXP3SR4ApnkQj8x4LsB_ORKBo")

	// Example cert serial is 0x21bd4, so a prefix of all zeroes should fetch it.
	retrievedCert, err := sa.GetCertificateByShortSerial("0000000000000000")
	test.AssertNotError(t, err, "Couldn't get www.eff.org.der by short serial")
	test.AssertByteEquals(t, certDER, retrievedCert.DER)

	retrievedCert, err = sa.GetCertificate("00000000000000000000000000021bd4")
	test.AssertNotError(t, err, "Couldn't get www.eff.org.der by full serial")
	test.AssertByteEquals(t, certDER, retrievedCert.DER)

	certificateStatus, err := sa.GetCertificateStatus("00000000000000000000000000021bd4")
	test.AssertNotError(t, err, "Couldn't get status for www.eff.org.der")
	test.Assert(t, !certificateStatus.SubscriberApproved, "SubscriberApproved should be false")
	test.Assert(t, certificateStatus.Status == core.OCSPStatusGood, "OCSP Status should be good")
	test.Assert(t, certificateStatus.OCSPLastUpdated.IsZero(), "OCSPLastUpdated should be nil")

	// Test cert generated locally by Boulder / CFSSL, serial "ff00000000000002238054509817da5a"
	certDER2, err := ioutil.ReadFile("test-cert.der")
	test.AssertNotError(t, err, "Couldn't read example cert DER")

	digest2, err := sa.AddCertificate(certDER2, reg.ID)
	test.AssertNotError(t, err, "Couldn't add test-cert.der")
	test.AssertEquals(t, digest2, "CMVYqWzyqUW7pfBF2CxL0Uk6I0Upsk7p4EWSnd_vYx4")

	// Example cert serial is 0x21bd4, so a prefix of all zeroes should fetch it.
	retrievedCert2, err := sa.GetCertificateByShortSerial("ff00000000000002")
	test.AssertNotError(t, err, "Couldn't get test-cert.der")
	test.AssertByteEquals(t, certDER2, retrievedCert2.DER)

	retrievedCert2, err = sa.GetCertificate("ff00000000000002238054509817da5a")
	test.AssertNotError(t, err, "Couldn't get test-cert.der")
	test.AssertByteEquals(t, certDER2, retrievedCert2.DER)

	certificateStatus2, err := sa.GetCertificateStatus("ff00000000000002238054509817da5a")
	test.AssertNotError(t, err, "Couldn't get status for test-cert.der")
	test.Assert(t, !certificateStatus2.SubscriberApproved, "SubscriberApproved should be false")
	test.Assert(t, certificateStatus2.Status == core.OCSPStatusGood, "OCSP Status should be good")
	test.Assert(t, certificateStatus2.OCSPLastUpdated.IsZero(), "OCSPLastUpdated should be nil")
}

// TestGetCertificateByShortSerial tests some failure conditions for GetCertificate.
// Success conditions are tested above in TestAddCertificate.
func TestGetCertificateByShortSerial(t *testing.T) {
	sa, cleanUp := initSA(t)
	defer cleanUp()

	_, err := sa.GetCertificateByShortSerial("")
	test.AssertError(t, err, "Should've failed on empty serial")

	_, err = sa.GetCertificateByShortSerial("01020304050607080102030405060708")
	test.AssertError(t, err, "Should've failed on too-long serial")
}

func TestDeniedCSR(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 512)
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "google.com"},
		DNSNames: []string{"badguys.com", "reallybad.com"},
	}
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, template, key)
	csr, _ := x509.ParseCertificateRequest(csrBytes)

	sa, cleanUp := initSA(t)
	defer cleanUp()

	exists, err := sa.AlreadyDeniedCSR(append(csr.DNSNames, csr.Subject.CommonName))
	test.AssertNotError(t, err, "AlreadyDeniedCSR failed")
	test.Assert(t, !exists, "Found non-existent CSR")
}

func TestUpdateOCSP(t *testing.T) {
	sa, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	// Add a cert to the DB to test with.
	certDER, err := ioutil.ReadFile("www.eff.org.der")
	test.AssertNotError(t, err, "Couldn't read example cert DER")
	_, err = sa.AddCertificate(certDER, reg.ID)
	test.AssertNotError(t, err, "Couldn't add www.eff.org.der")

	serial := "00000000000000000000000000021bd4"
	const ocspResponse = "this is a fake OCSP response"
	err = sa.UpdateOCSP(serial, []byte(ocspResponse))
	test.AssertNotError(t, err, "UpdateOCSP failed")

	certificateStatusObj, err := sa.dbMap.Get(core.CertificateStatus{}, serial)
	certificateStatus := certificateStatusObj.(*core.CertificateStatus)
	test.AssertNotError(t, err, "Failed to fetch certificate status")
	test.Assert(t,
		certificateStatus.OCSPLastUpdated.After(time.Now().Add(-time.Second)),
		"OCSP last updated too old.")

	var fetchedOcspResponse core.OCSPResponse
	err = sa.dbMap.SelectOne(&fetchedOcspResponse,
		`SELECT * from ocspResponses where serial = ? order by createdAt DESC limit 1;`,
		serial)
	test.AssertNotError(t, err, "Failed to fetch OCSP response")
	test.AssertEquals(t, ocspResponse, string(fetchedOcspResponse.Response))
}
