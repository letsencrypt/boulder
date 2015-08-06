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
	"testing"
	"time"

	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/mattn/go-sqlite3"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/test"
)

var log = mocks.UseMockLog()

func initSA(t *testing.T) *SQLStorageAuthority {
	sa, err := NewSQLStorageAuthority("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create SA")
	}
	if err = sa.CreateTablesIfNotExists(); err != nil {
		t.Fatalf("Failed to create SA")
	}
	return sa
}

var theKey = `{
    "kty": "RSA",
    "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
    "e": "AQAB"
}`

func TestAddRegistration(t *testing.T) {
	sa := initSA(t)

	var jwk jose.JsonWebKey
	err := json.Unmarshal([]byte(theKey), &jwk)
	if err != nil {
		t.Errorf("JSON unmarshal error: %+v", err)
		return
	}

	reg, err := sa.NewRegistration(core.Registration{
		Key: jwk,
	})
	test.AssertNotError(t, err, "Couldn't create new registration")
	test.Assert(t, reg.ID != 0, "ID shouldn't be 0")

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

	jwk.KeyID = "bad"
	_, err = sa.GetRegistrationByKey(jwk)
	test.AssertError(t, err, "Registration object for invalid key was returned")
}

func TestAddAuthorization(t *testing.T) {
	sa := initSA(t)

	PA := core.Authorization{}

	PA, err := sa.NewPendingAuthorization(PA)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	test.Assert(t, PA.ID != "", "ID shouldn't be blank")

	dbPa, err := sa.GetAuthorization(PA.ID)
	test.AssertNotError(t, err, "Couldn't get pending authorization with ID "+PA.ID)
	test.AssertMarshaledEquals(t, PA, dbPa)

	expectedPa := core.Authorization{ID: PA.ID}
	test.AssertMarshaledEquals(t, dbPa.ID, expectedPa.ID)

	var jwk jose.JsonWebKey
	err = json.Unmarshal([]byte(theKey), &jwk)
	if err != nil {
		t.Errorf("JSON unmarshal error: %+v", err)
		return
	}

	chall := core.SimpleHTTPChallenge()

	combos := make([][]int, 1)
	combos[0] = []int{0, 1}

	exp := time.Now().AddDate(0, 0, 1)
	identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "wut.com"}
	newPa := core.Authorization{ID: PA.ID, Identifier: identifier, RegistrationID: 0, Status: core.StatusPending, Expires: &exp, Challenges: []core.Challenge{chall}, Combinations: combos}
	err = sa.UpdatePendingAuthorization(newPa)
	test.AssertNotError(t, err, "Couldn't update pending authorization with ID "+PA.ID)

	newPa.Status = core.StatusValid
	err = sa.FinalizeAuthorization(newPa)
	test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+PA.ID)

	dbPa, err = sa.GetAuthorization(PA.ID)
	test.AssertNotError(t, err, "Couldn't get authorization with ID "+PA.ID)
}

func CreateDomainAuth(t *testing.T, domainName string, sa *SQLStorageAuthority) (authz core.Authorization) {
	// create pending auth
	authz, err := sa.NewPendingAuthorization(core.Authorization{})
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
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
	authz.RegistrationID = 42
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
	sa := initSA(t)

	// attempt to get unauthorized domain
	authz, err := sa.GetLatestValidAuthorization(0, core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "example.org"})
	test.AssertError(t, err, "Should not have found a valid auth for example.org")

	// authorize "example.org"
	authz = CreateDomainAuth(t, "example.org", sa)

	// finalize auth
	authz.Status = core.StatusValid
	err = sa.FinalizeAuthorization(authz)
	test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+authz.ID)

	// attempt to get authorized domain with wrong RegID
	authz, err = sa.GetLatestValidAuthorization(0, core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "example.org"})
	test.AssertError(t, err, "Should not have found a valid auth for example.org and regID 0")

	// get authorized domain
	authz, err = sa.GetLatestValidAuthorization(42, core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "example.org"})
	test.AssertNotError(t, err, "Should have found a valid auth for example.org and regID 42")
	test.AssertEquals(t, authz.Status, core.StatusValid)
	test.AssertEquals(t, authz.Identifier.Type, core.IdentifierDNS)
	test.AssertEquals(t, authz.Identifier.Value, "example.org")
	test.AssertEquals(t, authz.RegistrationID, int64(42))
}

// Ensure we get the latest valid authorization for an ident
func TestGetLatestValidAuthorizationMultiple(t *testing.T) {
	sa := initSA(t)
	domain := "example.org"
	ident := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: domain}
	regID := int64(42)
	var err error

	// create invalid authz
	authz := CreateDomainAuth(t, domain, sa)
	exp := time.Now().AddDate(0, 0, 10) // expire in 10 day
	authz.Expires = &exp
	authz.Status = core.StatusInvalid
	err = sa.FinalizeAuthorization(authz)
	test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+authz.ID)

	// should not get the auth
	authz, err = sa.GetLatestValidAuthorization(regID, ident)
	test.AssertError(t, err, "Should not have found a valid auth for "+domain)

	// create valid auth
	authz = CreateDomainAuth(t, domain, sa)
	exp = time.Now().AddDate(0, 0, 1) // expire in 1 day
	authz.Expires = &exp
	authz.Status = core.StatusValid
	err = sa.FinalizeAuthorization(authz)
	test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+authz.ID)

	// should get the valid auth even if it's expire date is lower than the invalid one
	authz, err = sa.GetLatestValidAuthorization(regID, ident)
	test.AssertNotError(t, err, "Should have found a valid auth for "+domain)
	test.AssertEquals(t, authz.Status, core.StatusValid)
	test.AssertEquals(t, authz.Identifier.Type, ident.Type)
	test.AssertEquals(t, authz.Identifier.Value, ident.Value)
	test.AssertEquals(t, authz.RegistrationID, regID)

	// create a newer auth
	newAuthz := CreateDomainAuth(t, domain, sa)
	exp = time.Now().AddDate(0, 0, 2) // expire in 2 day
	newAuthz.Expires = &exp
	newAuthz.Status = core.StatusValid
	err = sa.FinalizeAuthorization(newAuthz)
	test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+newAuthz.ID)

	authz, err = sa.GetLatestValidAuthorization(regID, ident)
	test.AssertNotError(t, err, "Should have found a valid auth for "+domain)
	test.AssertEquals(t, authz.Status, core.StatusValid)
	test.AssertEquals(t, authz.Identifier.Type, ident.Type)
	test.AssertEquals(t, authz.Identifier.Value, ident.Value)
	test.AssertEquals(t, authz.RegistrationID, regID)
	// make sure we got the latest auth
	test.AssertEquals(t, authz.ID, newAuthz.ID)
}

func TestAddCertificate(t *testing.T) {
	sa := initSA(t)

	// Create a new pending certificate
	pendingCert := core.Certificate{RegistrationID: 1}
	pendingCert, err := sa.NewPendingCertificate(pendingCert)
	test.AssertNotError(t, err, "Couldn't create a new pending cert")
	test.AssertEquals(t, pendingCert.RegistrationID, int64(1))
	test.AssertEquals(t, pendingCert.Status, core.StatusPending)
	test.AssertNotEquals(t, pendingCert.RequestID, "")
	test.Assert(t, core.LooksLikeAToken(pendingCert.RequestID), "Bad request ID in pending cert")

	// Try to retrieve the pending certificate
	retrieved, err := sa.GetCertificateByRequestID(pendingCert.RequestID)
	test.AssertNotError(t, err, "Couldn't retrieve pending certificate")
	test.AssertEquals(t, retrieved.RequestID, pendingCert.RequestID)
	test.AssertEquals(t, retrieved.Status, pendingCert.Status)

	// Try to finalize a certificate with non-final status
	err = sa.FinalizeCertificate(pendingCert)
	test.AssertError(t, err, "Finalized a cert that was still pending")

	// Try to finalize a certificate for which there is no pending cert
	pendingCert.Status = core.StatusInvalid
	err = sa.FinalizeCertificate(pendingCert)
	test.AssertNotError(t, err, "Failed to finalize on a valid request")

	// Try to retrieve the finalized certificate
	retrieved, err = sa.GetCertificateByRequestID(pendingCert.RequestID)
	test.AssertNotError(t, err, "Couldn't retrieve finalized certificate")
	test.AssertEquals(t, retrieved.RequestID, pendingCert.RequestID)
	test.AssertEquals(t, retrieved.Status, pendingCert.Status)

	// Try to finalize the same certificate twice
	err = sa.FinalizeCertificate(pendingCert)
	test.AssertError(t, err, "Allowed the same cert to finalize twice")

	// Insert a certificate with a serial number and test retrieval
	pendingCert = core.Certificate{RegistrationID: 1}
	pendingCert, err = sa.NewPendingCertificate(pendingCert)
	test.AssertNotError(t, err, "Failed to create new pending cert")

	pendingCert.Status = core.StatusValid
	pendingCert.Serial = "ff00000000000002238054509817da5a"
	pendingCert.DER = []byte{0x30, 0x00}
	err = sa.FinalizeCertificate(pendingCert)
	test.AssertNotError(t, err, "Failed to finalize pending cert")

	retrieved, err = sa.GetCertificateByShortSerial("ff00000000000002")
	test.AssertNotError(t, err, "Couldn't get certificate by short serial")
	test.AssertByteEquals(t, pendingCert.DER, retrieved.DER)

	retrieved, err = sa.GetCertificate("ff00000000000002238054509817da5a")
	test.AssertNotError(t, err, "Couldn't get certificate by short serial")
	test.AssertByteEquals(t, pendingCert.DER, retrieved.DER)

	certificateStatus, err := sa.GetCertificateStatus("ff00000000000002238054509817da5a")
	test.AssertNotError(t, err, "Couldn't get status for known valid certificate")
	test.Assert(t, !certificateStatus.SubscriberApproved, "SubscriberApproved should be false")
	test.Assert(t, certificateStatus.Status == core.OCSPStatusGood, "OCSP Status should be good")
	test.Assert(t, certificateStatus.OCSPLastUpdated.IsZero(), "OCSPLastUpdated should be nil")
}

// TestGetCertificateByShortSerial tests some failure conditions for GetCertificate.
// Success conditions are tested above in TestAddCertificate.
func TestGetCertificateByShortSerial(t *testing.T) {
	sa := initSA(t)

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

	sa := initSA(t)
	exists, err := sa.AlreadyDeniedCSR(append(csr.DNSNames, csr.Subject.CommonName))
	test.AssertNotError(t, err, "AlreadyDeniedCSR failed")
	test.Assert(t, !exists, "Found non-existent CSR")
}

func TestUpdateOCSP(t *testing.T) {
	sa := initSA(t)

	// Add a cert to the DB to test with.
	cert := core.Certificate{RegistrationID: 1}
	cert, err := sa.NewPendingCertificate(cert)
	test.AssertNotError(t, err, "Failed to create new pending cert")
	cert.Status = core.StatusValid
	cert.Serial = "ff00000000000002238054509817da5a"
	cert.DER = []byte{0x30, 0x00}
	err = sa.FinalizeCertificate(cert)
	test.AssertNotError(t, err, "Failed to finalize pending cert")

	const ocspResponse = "this is a fake OCSP response"
	err = sa.UpdateOCSP(cert.Serial, []byte(ocspResponse))
	test.AssertNotError(t, err, "UpdateOCSP failed")

	certificateStatusObj, err := sa.dbMap.Get(core.CertificateStatus{}, cert.Serial)
	certificateStatus := certificateStatusObj.(*core.CertificateStatus)
	test.AssertNotError(t, err, "Failed to fetch certificate status")
	test.Assert(t,
		certificateStatus.OCSPLastUpdated.After(time.Now().Add(-time.Second)),
		"OCSP last updated too old.")

	var fetchedOcspResponse core.OCSPResponse
	err = sa.dbMap.SelectOne(&fetchedOcspResponse,
		`SELECT * from ocspResponses where serial = ? order by createdAt DESC limit 1;`,
		cert.Serial)
	test.AssertNotError(t, err, "Failed to fetch OCSP response")
	test.AssertEquals(t, ocspResponse, string(fetchedOcspResponse.Response))
}
