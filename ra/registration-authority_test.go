// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ra

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"testing"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/signer/local"
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/mattn/go-sqlite3"
	"github.com/letsencrypt/boulder/ca"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/jose"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/policy"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test"
)


func assertAuthzEqual(t *testing.T, a1, a2 core.Authorization) {
	test.Assert(t, a1.ID == a2.ID, "ret != DB: ID")
	test.Assert(t, a1.Identifier == a2.Identifier, "ret != DB: Identifier")
	test.Assert(t, a1.Status == a2.Status, "ret != DB: Status")
	test.Assert(t, a1.Key.Equals(a2.Key), "ret != DB: Key")
	// Not testing: Contact, Challenges
}

func TestNewAuthorization(t *testing.T) {
	_, _, sa, ra := test.InitAuthorities(t)

	authz, err := ra.NewAuthorization(AuthzRequest, AccountKey)
	test.AssertNotError(t, err, "NewAuthorization failed")

	// Verify that returned authz same as DB
	dbAuthz, err := sa.GetAuthorization(authz.ID)
	test.AssertNotError(t, err, "Could not fetch authorization from database")
	assertAuthzEqual(t, authz, dbAuthz)

	// Verify that the returned authz has the right information
	test.Assert(t, authz.Key.Equals(AccountKey), "Initial authz did not get the right key")
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
	_, va, sa, ra := test.InitAuthorities(t)
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
	_, _, sa, ra := test.InitAuthorities(t)
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

func TestNewCertificate(t *testing.T) {
	_, _, sa, ra := test.InitAuthorities(t)
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

	cert, err := ra.NewCertificate(certRequest, AccountKey)
	test.AssertNotError(t, err, "Failed to issue certificate")
	parsedCert, err := x509.ParseCertificate(cert.DER)
	test.AssertNotError(t, err, "Failed to parse certificate")
	shortSerial := fmt.Sprintf("%032x", parsedCert.SerialNumber)[0:16]

	// Verify that cert shows up and is as expected
	dbCert, err := sa.GetCertificate(shortSerial)
	test.AssertNotError(t, err, fmt.Sprintf("Could not fetch certificate %032x from database",
		parsedCert.SerialNumber))
	test.Assert(t, bytes.Compare(cert.DER, dbCert) == 0, "Certificates differ")

	// TODO Test failure cases
	t.Log("DONE TestOnValidationUpdate")
}
