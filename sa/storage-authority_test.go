// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sa

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/mattn/go-sqlite3"
	"github.com/letsencrypt/boulder/core"
	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/square/go-jose"
	"github.com/letsencrypt/boulder/test"
	"io/ioutil"
	"testing"
)

func initSA(t *testing.T) (*SQLStorageAuthority) {
	sa, err := NewSQLStorageAuthority("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create SA")
	}
	if err = sa.InitTables(); err != nil {
		t.Fatalf("Failed to create SA")
	}
	return sa
}

var theKey string = `{
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
		ID: reg.ID,
		Key: jwk,
	}
	test.AssertEquals(t, dbReg.ID, expectedReg.ID)
	test.Assert(t, core.KeyDigestEquals(dbReg.Key, expectedReg.Key), "Stored key != expected")

	uu, err := url.Parse("test.com")
	u := core.AcmeURL(*uu)

	newReg := core.Registration{ID: reg.ID, Key: jwk, RecoveryToken: "RBNvo1WzZ4oRRq0W9", Contact: []core.AcmeURL{u}, Agreement: "yes"}
	err = sa.UpdateRegistration(newReg)
	test.AssertNotError(t, err, fmt.Sprintf("Couldn't get registration with ID %v", reg.ID))

	dbReg, err = sa.GetRegistrationByKey(jwk)
	test.AssertNotError(t, err, "Couldn't get registration by key")

	test.AssertEquals(t, dbReg.ID, newReg.ID)
	test.AssertEquals(t, dbReg.RecoveryToken, newReg.RecoveryToken)
	test.AssertEquals(t, dbReg.Agreement, newReg.Agreement)

	jwk.KeyID = "bad"
	_, err = sa.GetRegistrationByKey(jwk)
	test.AssertError(t, err, "Registration object for invalid key was returned")
}

func TestAddAuthorization(t *testing.T) {
	sa := initSA(t)

	paID, err := sa.NewPendingAuthorization()
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	test.Assert(t, paID != "", "ID shouldn't be blank")

	dbPa, err := sa.GetAuthorization(paID)
	test.AssertNotError(t, err, "Couldn't get pending authorization with ID "+paID)

	expectedPa := core.Authorization{ID: paID}
	test.AssertEquals(t, dbPa.ID, expectedPa.ID)

	var jwk jose.JsonWebKey
	err = json.Unmarshal([]byte(theKey), &jwk)
	if err != nil {
		t.Errorf("JSON unmarshal error: %+v", err)
		return
	}

	uu, err := url.Parse("test.com")
	u := core.AcmeURL(*uu)

	chall := core.Challenge{Type: "simpleHttps", Status: core.StatusPending, URI: u, Token: "THISWOULDNTBEAGOODTOKEN", Path: "test-me"}

	combos := make([][]int, 1)
	combos[0] = []int{0,1}


	newPa := core.Authorization{ID: paID, Identifier: core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "wut.com"}, RegistrationID: 0, Status: core.StatusPending, Expires: time.Now().AddDate(0, 0, 1), Challenges: []core.Challenge{chall}, Combinations: combos, Contact: []core.AcmeURL{u}}
	err = sa.UpdatePendingAuthorization(newPa)
	test.AssertNotError(t, err, "Couldn't update pending authorization with ID "+paID)

	newPa.Status = core.StatusValid
	err = sa.FinalizeAuthorization(newPa)
	test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+paID)

	dbPa, err = sa.GetAuthorization(paID)
	test.AssertNotError(t, err, "Couldn't get authorization with ID "+paID)
}

func TestAddCertificate(t *testing.T) {
	sa := initSA(t)

	// An example cert taken from EFF's website
	certDER, err := ioutil.ReadFile("www.eff.org.der")
	test.AssertNotError(t, err, "Couldn't read example cert DER")

	digest, err := sa.AddCertificate(certDER, 1)
	test.AssertNotError(t, err, "Couldn't add www.eff.org.der")
	test.AssertEquals(t, digest, "qWoItDZmR4P9eFbeYgXXP3SR4ApnkQj8x4LsB_ORKBo")

	// Example cert serial is 0x21bd4, so a prefix of all zeroes should fetch it.
	retrievedDER, err := sa.GetCertificateByShortSerial("0000000000000000")
	test.AssertNotError(t, err, "Couldn't get www.eff.org.der by short serial")
	test.AssertByteEquals(t, certDER, retrievedDER)

	retrievedDER, err = sa.GetCertificate("00000000000000000000000000021bd4")
	test.AssertNotError(t, err, "Couldn't get www.eff.org.der by full serial")
	test.AssertByteEquals(t, certDER, retrievedDER)

	certificateStatus, err := sa.GetCertificateStatus("00000000000000000000000000021bd4")
	test.AssertNotError(t, err, "Couldn't get status for www.eff.org.der")
	test.Assert(t, !certificateStatus.SubscriberApproved, "SubscriberApproved should be false")
	test.Assert(t, certificateStatus.Status == core.OCSPStatusGood, "OCSP Status should be good")
	test.Assert(t, certificateStatus.OCSPLastUpdated.IsZero(), "OCSPLastUpdated should be nil")

	// Test cert generated locally by Boulder / CFSSL, serial "ff00000000000002238054509817da5a"
	certDER2, err := ioutil.ReadFile("test-cert.der")
	test.AssertNotError(t, err, "Couldn't read example cert DER")

	digest2, err := sa.AddCertificate(certDER2, 1)
	test.AssertNotError(t, err, "Couldn't add test-cert.der")
	test.AssertEquals(t, digest2, "CMVYqWzyqUW7pfBF2CxL0Uk6I0Upsk7p4EWSnd_vYx4")

	// Example cert serial is 0x21bd4, so a prefix of all zeroes should fetch it.
	retrievedDER2, err := sa.GetCertificateByShortSerial("ff00000000000002")
	test.AssertNotError(t, err, "Couldn't get test-cert.der")
	test.AssertByteEquals(t, certDER2, retrievedDER2)

	retrievedDER2, err = sa.GetCertificate("ff00000000000002238054509817da5a")
	test.AssertNotError(t, err, "Couldn't get test-cert.der")
	test.AssertByteEquals(t, certDER2, retrievedDER2)

	certificateStatus2, err := sa.GetCertificateStatus("ff00000000000002238054509817da5a")
	test.AssertNotError(t, err, "Couldn't get status for test-cert.der")
	test.Assert(t, !certificateStatus2.SubscriberApproved, "SubscriberApproved should be false")
	test.Assert(t, certificateStatus2.Status == core.OCSPStatusGood, "OCSP Status should be good")
	test.Assert(t, certificateStatus2.OCSPLastUpdated.IsZero(), "OCSPLastUpdated should be nil")
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
		Subject: pkix.Name{CommonName: "google.com"},
		DNSNames: []string{"badguys.com", "reallybad.com"},
	}
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, template, key)
	csr, _ := x509.ParseCertificateRequest(csrBytes)

	sa := initSA(t)
	exists, err := sa.AlreadyDeniedCSR(append(csr.DNSNames, csr.Subject.CommonName))
	test.AssertNotError(t, err, "AlreadyDeniedCSR failed")
	test.Assert(t, !exists, "Found non-existent CSR")

	err = sa.AddDeniedCSR(append(csr.DNSNames, csr.Subject.CommonName))
	test.AssertNotError(t, err, "Couldn't add the denied CSR to the DB")

	exists, err = sa.AlreadyDeniedCSR(append(csr.DNSNames, csr.Subject.CommonName))
	test.AssertNotError(t, err, "AlreadyDeniedCSR failed")
	test.Assert(t, exists, "Couldn't find denied CSR in DB")
}
