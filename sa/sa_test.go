package sa

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/context"

	"github.com/jmhodges/clock"
	gorp "gopkg.in/go-gorp/gorp.v2"
	jose "gopkg.in/square/go-jose.v2"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/revocation"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
)

var log = blog.UseMock()
var ctx = context.Background()

// initSA constructs a SQLStorageAuthority and a clean up function
// that should be defer'ed to the end of the test.
func initSA(t *testing.T) (*SQLStorageAuthority, clock.FakeClock, func()) {
	dbMap, err := NewDbMap(vars.DBConnSA, 0)
	if err != nil {
		t.Fatalf("Failed to create dbMap: %s", err)
	}

	fc := clock.NewFake()
	fc.Set(time.Date(2015, 3, 4, 5, 0, 0, 0, time.UTC))

	sa, err := NewSQLStorageAuthority(dbMap, fc, log, metrics.NewNoopScope(), 1)
	if err != nil {
		t.Fatalf("Failed to create SA: %s", err)
	}

	cleanUp := test.ResetSATestDatabase(t)
	return sa, fc, cleanUp
}

var (
	anotherKey = `{
	"kty":"RSA",
	"n": "vd7rZIoTLEe-z1_8G1FcXSw9CQFEJgV4g9V277sER7yx5Qjz_Pkf2YVth6wwwFJEmzc0hoKY-MMYFNwBE4hQHw",
	"e":"AQAB"
}`
)

func TestAddRegistration(t *testing.T) {
	sa, clk, cleanUp := initSA(t)
	defer cleanUp()

	jwk := satest.GoodJWK()

	contact := "mailto:foo@example.com"
	contacts := &[]string{contact}
	reg, err := sa.NewRegistration(ctx, core.Registration{
		Key:       jwk,
		Contact:   contacts,
		InitialIP: net.ParseIP("43.34.43.34"),
	})
	if err != nil {
		t.Fatalf("Couldn't create new registration: %s", err)
	}
	test.Assert(t, reg.ID != 0, "ID shouldn't be 0")
	test.AssertDeepEquals(t, reg.Contact, contacts)

	_, err = sa.GetRegistration(ctx, 0)
	test.AssertError(t, err, "Registration object for ID 0 was returned")

	dbReg, err := sa.GetRegistration(ctx, reg.ID)
	test.AssertNotError(t, err, fmt.Sprintf("Couldn't get registration with ID %v", reg.ID))

	expectedReg := core.Registration{
		ID:        reg.ID,
		Key:       jwk,
		InitialIP: net.ParseIP("43.34.43.34"),
		CreatedAt: clk.Now(),
	}
	test.AssertEquals(t, dbReg.ID, expectedReg.ID)
	test.Assert(t, core.KeyDigestEquals(dbReg.Key, expectedReg.Key), "Stored key != expected")

	newReg := core.Registration{
		ID:        reg.ID,
		Key:       jwk,
		Contact:   &[]string{"test.com"},
		InitialIP: net.ParseIP("72.72.72.72"),
		Agreement: "yes",
	}
	err = sa.UpdateRegistration(ctx, newReg)
	test.AssertNotError(t, err, fmt.Sprintf("Couldn't get registration with ID %v", reg.ID))
	dbReg, err = sa.GetRegistrationByKey(ctx, jwk)
	test.AssertNotError(t, err, "Couldn't get registration by key")

	test.AssertEquals(t, dbReg.ID, newReg.ID)
	test.AssertEquals(t, dbReg.Agreement, newReg.Agreement)

	var anotherJWK jose.JSONWebKey
	err = json.Unmarshal([]byte(anotherKey), &anotherJWK)
	test.AssertNotError(t, err, "couldn't unmarshal anotherJWK")
	_, err = sa.GetRegistrationByKey(ctx, &anotherJWK)
	test.AssertError(t, err, "Registration object for invalid key was returned")
}

func TestNoSuchRegistrationErrors(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()

	_, err := sa.GetRegistration(ctx, 100)
	if !berrors.Is(err, berrors.NotFound) {
		t.Errorf("GetRegistration: expected a berrors.NotFound type error, got %T type error (%s)", err, err)
	}

	jwk := satest.GoodJWK()
	_, err = sa.GetRegistrationByKey(ctx, jwk)
	if !berrors.Is(err, berrors.NotFound) {
		t.Errorf("GetRegistrationByKey: expected a berrors.NotFound type error, got %T type error (%s)", err, err)
	}

	err = sa.UpdateRegistration(ctx, core.Registration{ID: 100, Key: jwk})
	if !berrors.Is(err, berrors.NotFound) {
		t.Errorf("UpdateRegistration: expected a berrors.NotFound type error, got %T type error (%v)", err, err)
	}
}

func TestCountPendingAuthorizations(t *testing.T) {
	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	expires := fc.Now().Add(time.Hour)
	pendingAuthz := core.Authorization{
		RegistrationID: reg.ID,
		Expires:        &expires,
	}

	pendingAuthz, err := sa.NewPendingAuthorization(ctx, pendingAuthz)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	count, err := sa.CountPendingAuthorizations(ctx, reg.ID)
	test.AssertNotError(t, err, "Couldn't count pending authorizations")
	test.AssertEquals(t, count, 0)

	pendingAuthz.Status = core.StatusPending
	pendingAuthz, err = sa.NewPendingAuthorization(ctx, pendingAuthz)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	count, err = sa.CountPendingAuthorizations(ctx, reg.ID)
	test.AssertNotError(t, err, "Couldn't count pending authorizations")
	test.AssertEquals(t, count, 1)

	fc.Add(2 * time.Hour)
	count, err = sa.CountPendingAuthorizations(ctx, reg.ID)
	test.AssertNotError(t, err, "Couldn't count pending authorizations")
	test.AssertEquals(t, count, 0)
}

func TestAddAuthorization(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	PA := core.Authorization{RegistrationID: reg.ID}

	PA, err := sa.NewPendingAuthorization(ctx, PA)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	test.Assert(t, PA.ID != "", "ID shouldn't be blank")

	dbPa, err := sa.GetAuthorization(ctx, PA.ID)
	test.AssertNotError(t, err, "Couldn't get pending authorization with ID "+PA.ID)
	test.AssertMarshaledEquals(t, PA, dbPa)

	expectedPa := core.Authorization{ID: PA.ID}
	test.AssertMarshaledEquals(t, dbPa.ID, expectedPa.ID)

	combos := make([][]int, 1)
	combos[0] = []int{0, 1}

	exp := time.Now().AddDate(0, 0, 1)
	identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "wut.com"}
	newPa := core.Authorization{ID: PA.ID, Identifier: identifier, RegistrationID: reg.ID, Status: core.StatusPending, Expires: &exp, Combinations: combos}

	newPa.Status = core.StatusValid
	err = sa.FinalizeAuthorization(ctx, newPa)
	test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+PA.ID)

	dbPa, err = sa.GetAuthorization(ctx, PA.ID)
	test.AssertNotError(t, err, "Couldn't get authorization with ID "+PA.ID)
}

func TestRecyclePendingDisabled(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	pendingAuthz, err := sa.NewPendingAuthorization(ctx, core.Authorization{RegistrationID: reg.ID})

	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	test.Assert(t, pendingAuthz.ID != "", "ID shouldn't be blank")

	pendingAuthz2, err := sa.NewPendingAuthorization(ctx, core.Authorization{RegistrationID: reg.ID})

	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	test.AssertNotEquals(t, pendingAuthz.ID, pendingAuthz2.ID)
}

func TestRecyclePendingEnabled(t *testing.T) {

	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	expires := fc.Now()
	authz := core.Authorization{
		RegistrationID: reg.ID,
		Identifier: core.AcmeIdentifier{
			Type:  "dns",
			Value: "example.letsencrypt.org",
		},
		Challenges: []core.Challenge{
			core.Challenge{
				URI:    "https://acme-example.letsencrypt.org/challenge123",
				Type:   "http-01",
				Status: "pending",
				Token:  "abc",
			},
		},
		Expires: &expires,
	}

	// Add expired authz
	_, err := sa.NewPendingAuthorization(ctx, authz)
	test.AssertNotError(t, err, "Couldn't create new expired pending authorization")

	// Add expected authz
	fc.Add(3 * time.Hour)
	expires = fc.Now().Add(2 * time.Hour) // magic pointer
	pendingAuthzA, err := sa.NewPendingAuthorization(ctx, authz)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	test.Assert(t, pendingAuthzA.ID != "", "ID shouldn't be blank")
	// Add extra authz for kicks
	pendingAuthzB, err := sa.NewPendingAuthorization(ctx, authz)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	test.Assert(t, pendingAuthzB.ID != "", "ID shouldn't be blank")
}

func CreateDomainAuth(t *testing.T, domainName string, sa *SQLStorageAuthority) (authz core.Authorization) {
	return CreateDomainAuthWithRegID(t, domainName, sa, 42)
}

func CreateDomainAuthWithRegID(t *testing.T, domainName string, sa *SQLStorageAuthority, regID int64) (authz core.Authorization) {
	exp := sa.clk.Now().AddDate(0, 0, 1) // expire in 1 day

	combos := make([][]int, 1)
	combos[0] = []int{0, 1}

	// create pending auth
	authz, err := sa.NewPendingAuthorization(ctx, core.Authorization{
		Status:         core.StatusPending,
		Expires:        &exp,
		Identifier:     core.AcmeIdentifier{Type: core.IdentifierDNS, Value: domainName},
		RegistrationID: regID,
		Challenges:     []core.Challenge{{}},
		Combinations:   combos,
	})
	if err != nil {
		t.Fatalf("Couldn't create new pending authorization: %s", err)
	}
	test.Assert(t, authz.ID != "", "ID shouldn't be blank")

	// prepare challenge for auth
	chall := core.Challenge{Type: "simpleHttp", Status: core.StatusValid, URI: domainName, Token: "THISWOULDNTBEAGOODTOKEN"}
	// Add some challenges
	authz.Challenges = []core.Challenge{chall}
	err = sa.UpdatePendingAuthorization(ctx, authz)
	test.AssertNotError(t, err, "Couldn't update pending authorization with ID "+authz.ID)

	return
}

// Ensure we get only valid authorization with correct RegID
func TestGetValidAuthorizationsBasic(t *testing.T) {
	sa, clk, cleanUp := initSA(t)
	defer cleanUp()

	// Attempt to get unauthorized domain.
	authzMap, err := sa.GetValidAuthorizations(ctx, 0, []string{"example.org"}, clk.Now())
	// Should get no results, but not error.
	test.AssertNotError(t, err, "Error getting valid authorizations")
	test.AssertEquals(t, len(authzMap), 0)

	reg := satest.CreateWorkingRegistration(t, sa)

	// authorize "example.org"
	authz := CreateDomainAuthWithRegID(t, "example.org", sa, reg.ID)

	// finalize auth
	authz.Status = core.StatusValid
	err = sa.FinalizeAuthorization(ctx, authz)
	test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+authz.ID)

	// attempt to get authorized domain with wrong RegID
	authzMap, err = sa.GetValidAuthorizations(ctx, 0, []string{"example.org"}, clk.Now())
	test.AssertNotError(t, err, "Error getting valid authorizations")
	test.AssertEquals(t, len(authzMap), 0)

	// get authorized domain
	authzMap, err = sa.GetValidAuthorizations(ctx, reg.ID, []string{"example.org"}, clk.Now())
	test.AssertNotError(t, err, "Should have found a valid auth for example.org and regID 42")
	test.AssertEquals(t, len(authzMap), 1)
	result := authzMap["example.org"]
	test.AssertEquals(t, result.Status, core.StatusValid)
	test.AssertEquals(t, result.Identifier.Type, core.IdentifierDNS)
	test.AssertEquals(t, result.Identifier.Value, "example.org")
	test.AssertEquals(t, result.RegistrationID, reg.ID)
}

func TestCountInvalidAuthorizations(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)

	key2 := new(jose.JSONWebKey)
	key2.Key = &rsa.PublicKey{N: big.NewInt(1), E: 3}
	reg2, err := sa.NewRegistration(context.Background(), core.Registration{
		Key:       key2,
		InitialIP: net.ParseIP("88.77.66.11"),
		CreatedAt: time.Date(2003, 5, 10, 0, 0, 0, 0, time.UTC),
		Status:    core.StatusValid,
	})
	test.AssertNotError(t, err, "making registration")

	baseTime := time.Date(2017, 3, 4, 5, 0, 0, 0, time.UTC)
	latest := baseTime.Add(3 * time.Hour)

	makeInvalidAuthz := func(regID int64, domain string, offset time.Duration) {
		authz := CreateDomainAuthWithRegID(t, domain, sa, regID)
		exp := baseTime.Add(offset)
		authz.Expires = &exp
		authz.Status = "invalid"
		err := sa.FinalizeAuthorization(ctx, authz)
		test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+authz.ID)
	}

	// We're going to count authzs for reg.ID and example.net, expiring between
	// baseTime and baseTime + 3 hours, so add two examples that should be counted
	// (1 hour from now and 2 hours from now), plus three that shouldn't be
	// counted (too far future, wrong domain name, and wrong ID).
	hostname := "example.net"
	makeInvalidAuthz(reg.ID, hostname, time.Hour)
	makeInvalidAuthz(reg.ID, hostname, 2*time.Hour)
	makeInvalidAuthz(reg.ID, hostname, 24*time.Hour)
	makeInvalidAuthz(reg.ID, "example.com", time.Hour)
	makeInvalidAuthz(reg2.ID, hostname, time.Hour)

	earliestNanos := baseTime.UnixNano()
	latestNanos := latest.UnixNano()

	count, err := sa.CountInvalidAuthorizations(context.Background(), &sapb.CountInvalidAuthorizationsRequest{
		RegistrationID: &reg.ID,
		Hostname:       &hostname,
		Range: &sapb.Range{
			Earliest: &earliestNanos,
			Latest:   &latestNanos,
		},
	})
	test.AssertNotError(t, err, "counting invalid authorizations")

	if *count.Count != 2 {
		t.Errorf("expected to count 2 invalid authorizations, counted %d instead", *count.Count)
	}
}

// Ensure we get the latest valid authorization for an ident
func TestGetValidAuthorizationsDuplicate(t *testing.T) {
	sa, clk, cleanUp := initSA(t)
	defer cleanUp()

	domain := "example.org"
	var err error

	reg := satest.CreateWorkingRegistration(t, sa)

	makeAuthz := func(daysToExpiry int, status core.AcmeStatus) core.Authorization {
		authz := CreateDomainAuthWithRegID(t, domain, sa, reg.ID)
		exp := clk.Now().AddDate(0, 0, daysToExpiry)
		authz.Expires = &exp
		authz.Status = status
		err = sa.FinalizeAuthorization(ctx, authz)
		test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+authz.ID)
		return authz
	}

	// create invalid authz
	makeAuthz(10, core.StatusInvalid)

	// should not get the auth
	authzMap, err := sa.GetValidAuthorizations(ctx, reg.ID, []string{domain}, clk.Now())
	test.AssertEquals(t, len(authzMap), 0)

	// create valid auth
	makeAuthz(1, core.StatusValid)

	// should get the valid auth even if it's expire date is lower than the invalid one
	authzMap, err = sa.GetValidAuthorizations(ctx, reg.ID, []string{domain}, clk.Now())
	test.AssertNotError(t, err, "Should have found a valid auth for "+domain)
	test.AssertEquals(t, len(authzMap), 1)
	result1 := authzMap[domain]
	test.AssertEquals(t, result1.Status, core.StatusValid)
	test.AssertEquals(t, result1.Identifier.Type, core.IdentifierDNS)
	test.AssertEquals(t, result1.Identifier.Value, domain)
	test.AssertEquals(t, result1.RegistrationID, reg.ID)

	// create a newer auth
	newAuthz := makeAuthz(2, core.StatusValid)

	authzMap, err = sa.GetValidAuthorizations(ctx, reg.ID, []string{domain}, clk.Now())
	test.AssertNotError(t, err, "Should have found a valid auth for "+domain)
	test.AssertEquals(t, len(authzMap), 1)
	result2 := authzMap[domain]
	test.AssertEquals(t, result2.Status, core.StatusValid)
	test.AssertEquals(t, result2.Identifier.Type, core.IdentifierDNS)
	test.AssertEquals(t, result2.Identifier.Value, domain)
	test.AssertEquals(t, result2.RegistrationID, reg.ID)
	// make sure we got the latest auth
	test.AssertEquals(t, result2.ID, newAuthz.ID)
}

// Fetch multiple authzs at once. Check that
func TestGetValidAuthorizationsMultiple(t *testing.T) {
	sa, clk, cleanUp := initSA(t)
	defer cleanUp()
	var err error

	reg := satest.CreateWorkingRegistration(t, sa)

	makeAuthz := func(daysToExpiry int, status core.AcmeStatus, domain string) core.Authorization {
		authz := CreateDomainAuthWithRegID(t, domain, sa, reg.ID)
		exp := clk.Now().AddDate(0, 0, daysToExpiry)
		authz.Expires = &exp
		authz.Status = status
		err = sa.FinalizeAuthorization(ctx, authz)
		test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+authz.ID)
		return authz
	}
	makeAuthz(1, core.StatusValid, "blog.example.com")
	makeAuthz(2, core.StatusInvalid, "blog.example.com")
	makeAuthz(5, core.StatusValid, "www.example.com")
	wwwAuthz := makeAuthz(6, core.StatusValid, "www.example.com")

	authzMap, err := sa.GetValidAuthorizations(ctx, reg.ID,
		[]string{"blog.example.com", "www.example.com", "absent.example.com"}, clk.Now())
	test.AssertNotError(t, err, "Couldn't get authorizations")
	test.AssertEquals(t, len(authzMap), 2)
	blogResult := authzMap["blog.example.com"]
	if blogResult == nil {
		t.Errorf("Didn't find blog.example.com in result")
	}
	if blogResult.Status == core.StatusInvalid {
		t.Errorf("Got invalid blogResult")
	}
	wwwResult := authzMap["www.example.com"]
	if wwwResult == nil {
		t.Errorf("Didn't find www.example.com in result")
	}
	test.AssertEquals(t, wwwResult.ID, wwwAuthz.ID)
}

func TestAddCertificate(t *testing.T) {
	sa, clk, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)

	// An example cert taken from EFF's website
	certDER, err := ioutil.ReadFile("www.eff.org.der")
	test.AssertNotError(t, err, "Couldn't read example cert DER")

	digest, err := sa.AddCertificate(ctx, certDER, reg.ID, nil)
	test.AssertNotError(t, err, "Couldn't add www.eff.org.der")
	test.AssertEquals(t, digest, "qWoItDZmR4P9eFbeYgXXP3SR4ApnkQj8x4LsB_ORKBo")

	retrievedCert, err := sa.GetCertificate(ctx, "000000000000000000000000000000021bd4")
	test.AssertNotError(t, err, "Couldn't get www.eff.org.der by full serial")
	test.AssertByteEquals(t, certDER, retrievedCert.DER)

	certificateStatus, err := sa.GetCertificateStatus(ctx, "000000000000000000000000000000021bd4")
	test.AssertNotError(t, err, "Couldn't get status for www.eff.org.der")
	test.Assert(t, certificateStatus.Status == core.OCSPStatusGood, "OCSP Status should be good")
	test.Assert(t, certificateStatus.OCSPLastUpdated.IsZero(), "OCSPLastUpdated should be nil")
	test.AssertEquals(t, certificateStatus.NotAfter, retrievedCert.Expires)

	// Test cert generated locally by Boulder / CFSSL, names [example.com,
	// www.example.com, admin.example.com]
	certDER2, err := ioutil.ReadFile("test-cert.der")
	test.AssertNotError(t, err, "Couldn't read example cert DER")
	serial := "ffdd9b8a82126d96f61d378d5ba99a0474f0"

	digest2, err := sa.AddCertificate(ctx, certDER2, reg.ID, nil)
	test.AssertNotError(t, err, "Couldn't add test-cert.der")
	test.AssertEquals(t, digest2, "vrlPN5wIPME1D2PPsCy-fGnTWh8dMyyYQcXPRkjHAQI")

	retrievedCert2, err := sa.GetCertificate(ctx, serial)
	test.AssertNotError(t, err, "Couldn't get test-cert.der")
	test.AssertByteEquals(t, certDER2, retrievedCert2.DER)

	certificateStatus2, err := sa.GetCertificateStatus(ctx, serial)
	test.AssertNotError(t, err, "Couldn't get status for test-cert.der")
	test.Assert(t, certificateStatus2.Status == core.OCSPStatusGood, "OCSP Status should be good")
	test.Assert(t, certificateStatus2.OCSPLastUpdated.IsZero(), "OCSPLastUpdated should be nil")

	// Test adding OCSP response with cert
	_ = features.Set(map[string]bool{"GenerateOCSPEarly": true})
	certDER3, err := ioutil.ReadFile("test-cert2.der")
	test.AssertNotError(t, err, "Couldn't read example cert DER")
	serial = "ffa0160630d618b2eb5c0510824b14274856"
	ocspResp := []byte{0, 0, 1}
	_, err = sa.AddCertificate(ctx, certDER3, reg.ID, ocspResp)
	test.AssertNotError(t, err, "Couldn't add test-cert2.der")

	certificateStatus3, err := sa.GetCertificateStatus(ctx, serial)
	test.AssertNotError(t, err, "Couldn't get status for test-cert2.der")
	test.Assert(
		t,
		bytes.Compare(certificateStatus3.OCSPResponse, ocspResp) == 0,
		fmt.Sprintf("OCSP responses don't match, expected: %x, got %x", certificateStatus3.OCSPResponse, ocspResp),
	)
	test.Assert(
		t,
		clk.Now().Equal(certificateStatus3.OCSPLastUpdated),
		fmt.Sprintf("OCSPLastUpdated doesn't match, expected %s, got %s", clk.Now(), certificateStatus3.OCSPLastUpdated),
	)
}

func TestCountCertificatesByNames(t *testing.T) {
	sa, clk, cleanUp := initSA(t)
	defer cleanUp()

	// Test cert generated locally by Boulder / CFSSL, names [example.com,
	// www.example.com, admin.example.com]
	certDER, err := ioutil.ReadFile("test-cert.der")
	test.AssertNotError(t, err, "Couldn't read example cert DER")

	cert, err := x509.ParseCertificate(certDER)
	test.AssertNotError(t, err, "Couldn't parse example cert DER")

	// Set the test clock's time to the time from the test certificate
	clk.Add(-clk.Now().Sub(cert.NotBefore))
	now := clk.Now()
	yesterday := clk.Now().Add(-24 * time.Hour)
	twoDaysAgo := clk.Now().Add(-48 * time.Hour)
	tomorrow := clk.Now().Add(24 * time.Hour)

	// Count for a name that doesn't have any certs
	counts, err := sa.CountCertificatesByNames(ctx, []string{"example.com"}, yesterday, now)
	test.AssertNotError(t, err, "Error counting certs.")
	test.AssertEquals(t, len(counts), 1)
	test.AssertEquals(t, *counts[0].Name, "example.com")
	test.AssertEquals(t, *counts[0].Count, int64(0))

	// Add the test cert and query for its names.
	reg := satest.CreateWorkingRegistration(t, sa)
	_, err = sa.AddCertificate(ctx, certDER, reg.ID, nil)
	test.AssertNotError(t, err, "Couldn't add test-cert.der")

	// Time range including now should find the cert
	counts, err = sa.CountCertificatesByNames(ctx, []string{"example.com"}, yesterday, now)
	test.AssertEquals(t, len(counts), 1)
	test.AssertEquals(t, *counts[0].Name, "example.com")
	test.AssertEquals(t, *counts[0].Count, int64(1))

	// Time range between two days ago and yesterday should not.
	counts, err = sa.CountCertificatesByNames(ctx, []string{"example.com"}, twoDaysAgo, yesterday)
	test.AssertNotError(t, err, "Error counting certs.")
	test.AssertEquals(t, len(counts), 1)
	test.AssertEquals(t, *counts[0].Name, "example.com")
	test.AssertEquals(t, *counts[0].Count, int64(0))

	// Time range between now and tomorrow also should not (time ranges are
	// inclusive at the tail end, but not the beginning end).
	counts, err = sa.CountCertificatesByNames(ctx, []string{"example.com"}, now, tomorrow)
	test.AssertNotError(t, err, "Error counting certs.")
	test.AssertEquals(t, len(counts), 1)
	test.AssertEquals(t, *counts[0].Name, "example.com")
	test.AssertEquals(t, *counts[0].Count, int64(0))

	// Add a second test cert (for example.co.bn) and query for multiple names.
	names := []string{"example.com", "foo.com", "example.co.bn"}

	// Override countCertificatesByName with an implementation of certCountFunc
	// that will block forever if it's called in serial, but will succeed if
	// called in parallel.
	var interlocker sync.WaitGroup
	interlocker.Add(len(names))
	sa.parallelismPerRPC = len(names)
	oldCertCountFunc := sa.countCertificatesByName
	sa.countCertificatesByName = func(domain string, earliest, latest time.Time) (int, error) {
		interlocker.Done()
		interlocker.Wait()
		return oldCertCountFunc(domain, earliest, latest)
	}

	certDER2, err := ioutil.ReadFile("test-cert2.der")
	test.AssertNotError(t, err, "Couldn't read test-cert2.der")
	_, err = sa.AddCertificate(ctx, certDER2, reg.ID, nil)
	test.AssertNotError(t, err, "Couldn't add test-cert2.der")
	counts, err = sa.CountCertificatesByNames(ctx, names, yesterday, now.Add(10000*time.Hour))
	test.AssertNotError(t, err, "Error counting certs.")
	test.AssertEquals(t, len(counts), 3)

	expected := map[string]int{
		"example.co.bn": 1,
		"foo.com":       0,
		"example.com":   1,
	}
	for _, entry := range counts {
		domain := *entry.Name
		actualCount := *entry.Count
		expectedCount := int64(expected[domain])
		test.AssertEquals(t, actualCount, expectedCount)
	}
}

const (
	sctVersion    = 0
	sctTimestamp  = 1435787268907
	sctLogID      = "aPaY+B9kgr46jO65KB1M/HFRXWeT1ETRCmesu09P+8Q="
	sctSignature  = "BAMASDBGAiEA/4kz9wQq3NhvZ6VlOmjq2Z9MVHGrUjF8uxUG9n1uRc4CIQD2FYnnszKXrR9AP5kBWmTgh3fXy+VlHK8HZXfbzdFf7g=="
	sctCertSerial = "ff000000000000012607e11a78ac01f9"
)

func TestAddSCTReceipt(t *testing.T) {
	sigBytes, err := base64.StdEncoding.DecodeString(sctSignature)
	test.AssertNotError(t, err, "Failed to decode SCT signature")
	sct := core.SignedCertificateTimestamp{
		SCTVersion:        sctVersion,
		LogID:             sctLogID,
		Timestamp:         sctTimestamp,
		Signature:         sigBytes,
		CertificateSerial: sctCertSerial,
	}
	sa, _, cleanup := initSA(t)
	defer cleanup()
	err = sa.AddSCTReceipt(ctx, sct)
	test.AssertNotError(t, err, "Failed to add SCT receipt")
	// Append only and unique on signature and across LogID and CertificateSerial
	err = sa.AddSCTReceipt(ctx, sct)
	test.AssertNotError(t, err, "Incorrectly returned error on duplicate SCT receipt")
}

func TestGetSCTReceipt(t *testing.T) {
	sigBytes, err := base64.StdEncoding.DecodeString(sctSignature)
	test.AssertNotError(t, err, "Failed to decode SCT signature")
	sct := core.SignedCertificateTimestamp{
		SCTVersion:        sctVersion,
		LogID:             sctLogID,
		Timestamp:         sctTimestamp,
		Signature:         sigBytes,
		CertificateSerial: sctCertSerial,
	}
	sa, _, cleanup := initSA(t)
	defer cleanup()
	err = sa.AddSCTReceipt(ctx, sct)
	test.AssertNotError(t, err, "Failed to add SCT receipt")

	sqlSCT, err := sa.GetSCTReceipt(ctx, sctCertSerial, sctLogID)
	test.AssertNotError(t, err, "Failed to get existing SCT receipt")
	test.Assert(t, sqlSCT.SCTVersion == sct.SCTVersion, "Invalid SCT version")
	test.Assert(t, sqlSCT.LogID == sct.LogID, "Invalid log ID")
	test.Assert(t, sqlSCT.Timestamp == sct.Timestamp, "Invalid timestamp")
	test.Assert(t, bytes.Compare(sqlSCT.Signature, sct.Signature) == 0, "Invalid signature")
	test.Assert(t, sqlSCT.CertificateSerial == sct.CertificateSerial, "Invalid certificate serial")
}

func TestMarkCertificateRevoked(t *testing.T) {
	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	// Add a cert to the DB to test with.
	certDER, err := ioutil.ReadFile("www.eff.org.der")
	test.AssertNotError(t, err, "Couldn't read example cert DER")
	_, err = sa.AddCertificate(ctx, certDER, reg.ID, nil)
	test.AssertNotError(t, err, "Couldn't add www.eff.org.der")

	serial := "000000000000000000000000000000021bd4"
	const ocspResponse = "this is a fake OCSP response"

	certificateStatusObj, err := sa.GetCertificateStatus(ctx, serial)
	test.AssertEquals(t, certificateStatusObj.Status, core.OCSPStatusGood)

	fc.Add(1 * time.Hour)

	err = sa.MarkCertificateRevoked(ctx, serial, revocation.KeyCompromise)
	test.AssertNotError(t, err, "MarkCertificateRevoked failed")

	certificateStatusObj, err = sa.GetCertificateStatus(ctx, serial)
	test.AssertNotError(t, err, "Failed to fetch certificate status")

	if revocation.KeyCompromise != certificateStatusObj.RevokedReason {
		t.Errorf("RevokedReasons, expected %v, got %v", revocation.KeyCompromise, certificateStatusObj.RevokedReason)
	}
	if !fc.Now().Equal(certificateStatusObj.RevokedDate) {
		t.Errorf("RevokedData, expected %s, got %s", fc.Now(), certificateStatusObj.RevokedDate)
	}
}

func TestCountCertificates(t *testing.T) {
	sa, fc, cleanUp := initSA(t)
	defer cleanUp()
	fc.Add(time.Hour * 24)
	now := fc.Now()
	count, err := sa.CountCertificatesRange(ctx, now.Add(-24*time.Hour), now)
	test.AssertNotError(t, err, "Couldn't get certificate count for the last 24hrs")
	test.AssertEquals(t, count, int64(0))

	reg := satest.CreateWorkingRegistration(t, sa)
	// Add a cert to the DB to test with.
	certDER, err := ioutil.ReadFile("www.eff.org.der")
	test.AssertNotError(t, err, "Couldn't read example cert DER")
	_, err = sa.AddCertificate(ctx, certDER, reg.ID, nil)
	test.AssertNotError(t, err, "Couldn't add www.eff.org.der")

	fc.Add(2 * time.Hour)
	now = fc.Now()
	count, err = sa.CountCertificatesRange(ctx, now.Add(-24*time.Hour), now)
	test.AssertNotError(t, err, "Couldn't get certificate count for the last 24hrs")
	test.AssertEquals(t, count, int64(1))

	fc.Add(24 * time.Hour)
	now = fc.Now()
	count, err = sa.CountCertificatesRange(ctx, now.Add(-24*time.Hour), now)
	test.AssertNotError(t, err, "Couldn't get certificate count for the last 24hrs")
	test.AssertEquals(t, count, int64(0))
}

func TestCountRegistrationsByIP(t *testing.T) {
	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	contact := "mailto:foo@example.com"

	// Create one IPv4 registration
	_, err := sa.NewRegistration(ctx, core.Registration{
		Key:       &jose.JSONWebKey{Key: &rsa.PublicKey{N: big.NewInt(1), E: 1}},
		Contact:   &[]string{contact},
		InitialIP: net.ParseIP("43.34.43.34"),
	})
	// Create two IPv6 registrations, both within the same /48
	test.AssertNotError(t, err, "Couldn't insert registration")
	_, err = sa.NewRegistration(ctx, core.Registration{
		Key:       &jose.JSONWebKey{Key: &rsa.PublicKey{N: big.NewInt(2), E: 1}},
		Contact:   &[]string{contact},
		InitialIP: net.ParseIP("2001:cdba:1234:5678:9101:1121:3257:9652"),
	})
	test.AssertNotError(t, err, "Couldn't insert registration")
	_, err = sa.NewRegistration(ctx, core.Registration{
		Key:       &jose.JSONWebKey{Key: &rsa.PublicKey{N: big.NewInt(3), E: 1}},
		Contact:   &[]string{contact},
		InitialIP: net.ParseIP("2001:cdba:1234:5678:9101:1121:3257:9653"),
	})
	test.AssertNotError(t, err, "Couldn't insert registration")

	earliest := fc.Now().Add(-time.Hour * 24)
	latest := fc.Now()

	// There should be 0 registrations for an IPv4 address we didn't add
	// a registration for
	count, err := sa.CountRegistrationsByIP(ctx, net.ParseIP("1.1.1.1"), earliest, latest)
	test.AssertNotError(t, err, "Failed to count registrations")
	test.AssertEquals(t, count, 0)
	// There should be 1 registration for the IPv4 address we did add
	// a registration for
	count, err = sa.CountRegistrationsByIP(ctx, net.ParseIP("43.34.43.34"), earliest, latest)
	test.AssertNotError(t, err, "Failed to count registrations")
	test.AssertEquals(t, count, 1)
	// There should be 1 registration for the first IPv6 address we added
	// a registration for
	count, err = sa.CountRegistrationsByIP(ctx, net.ParseIP("2001:cdba:1234:5678:9101:1121:3257:9652"), earliest, latest)
	test.AssertNotError(t, err, "Failed to count registrations")
	test.AssertEquals(t, count, 1)
	// There should be 1 registration for the second IPv6 address we added
	// a registration for as well
	count, err = sa.CountRegistrationsByIP(ctx, net.ParseIP("2001:cdba:1234:5678:9101:1121:3257:9653"), earliest, latest)
	test.AssertNotError(t, err, "Failed to count registrations")
	test.AssertEquals(t, count, 1)
	// There should be 0 registrations for an IPv6 address in the same /48 as the
	// two IPv6 addresses with registrations
	count, err = sa.CountRegistrationsByIP(ctx, net.ParseIP("2001:cdba:1234:0000:0000:0000:0000:0000"), earliest, latest)
	test.AssertNotError(t, err, "Failed to count registrations")
	test.AssertEquals(t, count, 0)
}

func TestCountRegistrationsByIPRange(t *testing.T) {
	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	contact := "mailto:foo@example.com"

	// Create one IPv4 registration
	_, err := sa.NewRegistration(ctx, core.Registration{
		Key:       &jose.JSONWebKey{Key: &rsa.PublicKey{N: big.NewInt(1), E: 1}},
		Contact:   &[]string{contact},
		InitialIP: net.ParseIP("43.34.43.34"),
	})
	// Create two IPv6 registrations, both within the same /48
	test.AssertNotError(t, err, "Couldn't insert registration")
	_, err = sa.NewRegistration(ctx, core.Registration{
		Key:       &jose.JSONWebKey{Key: &rsa.PublicKey{N: big.NewInt(2), E: 1}},
		Contact:   &[]string{contact},
		InitialIP: net.ParseIP("2001:cdba:1234:5678:9101:1121:3257:9652"),
	})
	test.AssertNotError(t, err, "Couldn't insert registration")
	_, err = sa.NewRegistration(ctx, core.Registration{
		Key:       &jose.JSONWebKey{Key: &rsa.PublicKey{N: big.NewInt(3), E: 1}},
		Contact:   &[]string{contact},
		InitialIP: net.ParseIP("2001:cdba:1234:5678:9101:1121:3257:9653"),
	})
	test.AssertNotError(t, err, "Couldn't insert registration")

	earliest := fc.Now().Add(-time.Hour * 24)
	latest := fc.Now()

	// There should be 0 registrations in the range for an IPv4 address we didn't
	// add a registration for
	count, err := sa.CountRegistrationsByIPRange(ctx, net.ParseIP("1.1.1.1"), earliest, latest)
	test.AssertNotError(t, err, "Failed to count registrations")
	test.AssertEquals(t, count, 0)
	// There should be 1 registration in the range for the IPv4 address we did
	// add a registration for
	count, err = sa.CountRegistrationsByIPRange(ctx, net.ParseIP("43.34.43.34"), earliest, latest)
	test.AssertNotError(t, err, "Failed to count registrations")
	test.AssertEquals(t, count, 1)
	// There should be 2 registrations in the range for the first IPv6 address we added
	// a registration for because it's in the same /48
	count, err = sa.CountRegistrationsByIPRange(ctx, net.ParseIP("2001:cdba:1234:5678:9101:1121:3257:9652"), earliest, latest)
	test.AssertNotError(t, err, "Failed to count registrations")
	test.AssertEquals(t, count, 2)
	// There should be 2 registrations in the range for the second IPv6 address
	// we added a registration for as well, because it too is in the same /48
	count, err = sa.CountRegistrationsByIPRange(ctx, net.ParseIP("2001:cdba:1234:5678:9101:1121:3257:9653"), earliest, latest)
	test.AssertNotError(t, err, "Failed to count registrations")
	test.AssertEquals(t, count, 2)
	// There should also be 2 registrations in the range for an arbitrary IPv6 address in
	// the same /48 as the registrations we added
	count, err = sa.CountRegistrationsByIPRange(ctx, net.ParseIP("2001:cdba:1234:0000:0000:0000:0000:0000"), earliest, latest)
	test.AssertNotError(t, err, "Failed to count registrations")
	test.AssertEquals(t, count, 2)
}

func TestRevokeAuthorizationsByDomain(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	PA1 := CreateDomainAuthWithRegID(t, "a.com", sa, reg.ID)
	PA2 := CreateDomainAuthWithRegID(t, "a.com", sa, reg.ID)

	PA2.Status = core.StatusValid
	err := sa.FinalizeAuthorization(ctx, PA2)
	test.AssertNotError(t, err, "Failed to finalize authorization")

	ident := core.AcmeIdentifier{Value: "a.com", Type: core.IdentifierDNS}
	ar, par, err := sa.RevokeAuthorizationsByDomain(ctx, ident)
	test.AssertNotError(t, err, "Failed to revoke authorizations for a.com")
	test.AssertEquals(t, ar, int64(1))
	test.AssertEquals(t, par, int64(1))

	PA, err := sa.GetAuthorization(ctx, PA1.ID)
	test.AssertNotError(t, err, "Failed to retrieve pending authorization")
	FA, err := sa.GetAuthorization(ctx, PA2.ID)
	test.AssertNotError(t, err, "Failed to retrieve finalized authorization")

	test.AssertEquals(t, PA.Status, core.StatusRevoked)
	test.AssertEquals(t, FA.Status, core.StatusRevoked)
}

func TestFQDNSets(t *testing.T) {
	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	tx, err := sa.dbMap.Begin()
	test.AssertNotError(t, err, "Failed to open transaction")
	names := []string{"a.example.com", "B.example.com"}
	expires := fc.Now().Add(time.Hour * 2).UTC()
	issued := fc.Now()
	err = addFQDNSet(tx, names, "serial", issued, expires)
	test.AssertNotError(t, err, "Failed to add name set")
	test.AssertNotError(t, tx.Commit(), "Failed to commit transaction")

	// only one valid
	threeHours := time.Hour * 3
	count, err := sa.CountFQDNSets(ctx, threeHours, names)
	test.AssertNotError(t, err, "Failed to count name sets")
	test.AssertEquals(t, count, int64(1))

	// check hash isn't affected by changing name order/casing
	count, err = sa.CountFQDNSets(ctx, threeHours, []string{"b.example.com", "A.example.COM"})
	test.AssertNotError(t, err, "Failed to count name sets")
	test.AssertEquals(t, count, int64(1))

	// add another valid set
	tx, err = sa.dbMap.Begin()
	test.AssertNotError(t, err, "Failed to open transaction")
	err = addFQDNSet(tx, names, "anotherSerial", issued, expires)
	test.AssertNotError(t, err, "Failed to add name set")
	test.AssertNotError(t, tx.Commit(), "Failed to commit transaction")

	// only two valid
	count, err = sa.CountFQDNSets(ctx, threeHours, names)
	test.AssertNotError(t, err, "Failed to count name sets")
	test.AssertEquals(t, count, int64(2))

	// add an expired set
	tx, err = sa.dbMap.Begin()
	test.AssertNotError(t, err, "Failed to open transaction")
	err = addFQDNSet(
		tx,
		names,
		"yetAnotherSerial",
		issued.Add(-threeHours),
		expires.Add(-threeHours),
	)
	test.AssertNotError(t, err, "Failed to add name set")
	test.AssertNotError(t, tx.Commit(), "Failed to commit transaction")

	// only two valid
	count, err = sa.CountFQDNSets(ctx, threeHours, names)
	test.AssertNotError(t, err, "Failed to count name sets")
	test.AssertEquals(t, count, int64(2))
}

func TestFQDNSetsExists(t *testing.T) {
	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	names := []string{"a.example.com", "B.example.com"}
	exists, err := sa.FQDNSetExists(ctx, names)
	test.AssertNotError(t, err, "Failed to check FQDN set existence")
	test.Assert(t, !exists, "FQDN set shouldn't exist")

	tx, err := sa.dbMap.Begin()
	test.AssertNotError(t, err, "Failed to open transaction")
	expires := fc.Now().Add(time.Hour * 2).UTC()
	issued := fc.Now()
	err = addFQDNSet(tx, names, "serial", issued, expires)
	test.AssertNotError(t, err, "Failed to add name set")
	test.AssertNotError(t, tx.Commit(), "Failed to commit transaction")

	exists, err = sa.FQDNSetExists(ctx, names)
	test.AssertNotError(t, err, "Failed to check FQDN set existence")
	test.Assert(t, exists, "FQDN set does exist")
}

type execRecorder struct {
	query string
	args  []interface{}
}

func (e *execRecorder) Exec(query string, args ...interface{}) (sql.Result, error) {
	e.query = query
	e.args = args
	return nil, nil
}

func TestAddIssuedNames(t *testing.T) {
	var e execRecorder
	err := addIssuedNames(&e, &x509.Certificate{
		DNSNames: []string{
			"example.co.uk",
			"example.xyz",
		},
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Date(2015, 3, 4, 5, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	expected := "INSERT INTO issuedNames (reversedName, serial, notBefore) VALUES (?, ?, ?), (?, ?, ?);"
	if e.query != expected {
		t.Errorf("Wrong query: got %q, expected %q", e.query, expected)
	}
	expectedArgs := []interface{}{
		"uk.co.example",
		"000000000000000000000000000000000001",
		time.Date(2015, 3, 4, 5, 0, 0, 0, time.UTC),
		"xyz.example",
		"000000000000000000000000000000000001",
		time.Date(2015, 3, 4, 5, 0, 0, 0, time.UTC),
	}
	if !reflect.DeepEqual(e.args, expectedArgs) {
		t.Errorf("Wrong args: got\n%#v, expected\n%#v", e.args, expectedArgs)
	}
}

func TestPreviousCertificateExists(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)

	// An example cert taken from EFF's website
	certDER, err := ioutil.ReadFile("www.eff.org.der")
	test.AssertNotError(t, err, "reading cert DER")

	_, err = sa.AddCertificate(ctx, certDER, reg.ID, nil)
	test.AssertNotError(t, err, "calling AddCertificate")

	cases := []struct {
		name     string
		domain   string
		regID    int64
		expected bool
	}{
		{"matches", "www.eff.org", reg.ID, true},
		{"wrongDomain", "wwoof.org", reg.ID, false},
		{"wrongAccount", "www.eff.org", 3333, false},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			exists, err := sa.PreviousCertificateExists(context.Background(),
				&sapb.PreviousCertificateExistsRequest{
					Domain: &testCase.domain,
					RegID:  &testCase.regID,
				})
			test.AssertNotError(t, err, "calling PreviousCertificateExists")
			if *exists.Exists != testCase.expected {
				t.Errorf("wanted %v got %v", testCase.expected, *exists.Exists)
			}
		})
	}
}

func TestDeactivateAuthorization(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	PA := core.Authorization{RegistrationID: reg.ID}

	PA, err := sa.NewPendingAuthorization(ctx, PA)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	test.Assert(t, PA.ID != "", "ID shouldn't be blank")

	dbPa, err := sa.GetAuthorization(ctx, PA.ID)
	test.AssertNotError(t, err, "Couldn't get pending authorization with ID "+PA.ID)
	test.AssertMarshaledEquals(t, PA, dbPa)

	expectedPa := core.Authorization{ID: PA.ID}
	test.AssertMarshaledEquals(t, dbPa.ID, expectedPa.ID)

	combos := make([][]int, 1)
	combos[0] = []int{0, 1}

	exp := time.Now().AddDate(0, 0, 1)
	identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "wut.com"}
	newPa := core.Authorization{
		ID:             PA.ID,
		Identifier:     identifier,
		RegistrationID: reg.ID,
		Status:         core.StatusPending,
		Expires:        &exp,
		Combinations:   combos,
	}

	newPa.Status = core.StatusValid
	err = sa.FinalizeAuthorization(ctx, newPa)
	test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+PA.ID)

	dbPa, err = sa.GetAuthorization(ctx, PA.ID)
	test.AssertNotError(t, err, "Couldn't get authorization with ID "+PA.ID)

	err = sa.DeactivateAuthorization(ctx, dbPa.ID)
	test.AssertNotError(t, err, "Couldn't deactivate valid authorization with ID "+PA.ID)

	dbPa, err = sa.GetAuthorization(ctx, PA.ID)
	test.AssertNotError(t, err, "Couldn't get authorization with ID "+PA.ID)
	test.AssertEquals(t, dbPa.Status, core.StatusDeactivated)

	PA.Status = core.StatusPending
	PA, err = sa.NewPendingAuthorization(ctx, PA)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	test.Assert(t, PA.ID != "", "ID shouldn't be blank")

	err = sa.DeactivateAuthorization(ctx, PA.ID)
	test.AssertNotError(t, err, "Couldn't deactivate pending authorization with ID "+PA.ID)

	dbPa, err = sa.GetAuthorization(ctx, PA.ID)
	test.AssertNotError(t, err, "Couldn't get authorization with ID "+PA.ID)
	test.AssertEquals(t, dbPa.Status, core.StatusDeactivated)
}

func TestDeactivateAccount(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)

	err := sa.DeactivateRegistration(context.Background(), reg.ID)
	test.AssertNotError(t, err, "DeactivateRegistration failed")

	dbReg, err := sa.GetRegistration(context.Background(), reg.ID)
	test.AssertNotError(t, err, "GetRegistration failed")
	test.AssertEquals(t, dbReg.Status, core.StatusDeactivated)
}

func TestReverseName(t *testing.T) {
	testCases := []struct {
		inputDomain   string
		inputReversed string
	}{
		{"", ""},
		{"...", "..."},
		{"com", "com"},
		{"example.com", "com.example"},
		{"www.example.com", "com.example.www"},
		{"world.wide.web.example.com", "com.example.web.wide.world"},
	}

	for _, tc := range testCases {
		output := ReverseName(tc.inputDomain)
		test.AssertEquals(t, output, tc.inputReversed)
	}
}

type fqdnTestcase struct {
	Serial       string
	Names        []string
	ExpectedHash setHash
	Issued       time.Time
	Expires      time.Time
}

func setupFQDNSets(t *testing.T, db *gorp.DbMap, fc clock.FakeClock) map[string]fqdnTestcase {
	namesA := []string{"a.example.com", "B.example.com"}
	namesB := []string{"example.org"}
	namesC := []string{"letsencrypt.org"}
	expectedHashA := setHash{0x92, 0xc7, 0xf2, 0x47, 0xbd, 0x1e, 0xea, 0x8d, 0x52, 0x7f, 0xb0, 0x59, 0x19, 0xe9, 0xbe, 0x81, 0x78, 0x88, 0xe6, 0xf7, 0x55, 0xf0, 0x1c, 0xc9, 0x63, 0x15, 0x5f, 0x8e, 0x52, 0xae, 0x95, 0xc1}
	expectedHashB := setHash{0xbf, 0xab, 0xc3, 0x74, 0x32, 0x95, 0x8b, 0x6, 0x33, 0x60, 0xd3, 0xad, 0x64, 0x61, 0xc9, 0xc4, 0x73, 0x5a, 0xe7, 0xf8, 0xed, 0xd4, 0x65, 0x92, 0xa5, 0xe0, 0xf0, 0x14, 0x52, 0xb2, 0xe4, 0xb5}
	expectedHashC := setHash{0xf2, 0xbb, 0x7b, 0xab, 0x8, 0x2c, 0x18, 0xee, 0x8, 0x97, 0x17, 0xbe, 0x67, 0xd7, 0x12, 0x14, 0xaa, 0x4, 0xac, 0xe2, 0x29, 0x2a, 0x67, 0x2c, 0x37, 0x2c, 0xf3, 0x33, 0xe1, 0xb0, 0xd8, 0xe7}

	now := fc.Now()

	testcases := map[string]fqdnTestcase{
		// One test case with serial "a" issued now and expiring in two hours for
		// namesA
		"a": fqdnTestcase{
			Serial:       "a",
			Names:        namesA,
			ExpectedHash: expectedHashA,
			Issued:       now,
			Expires:      now.Add(time.Hour * 2).UTC(),
		},
		// One test case with serial "b", issued one hour from now and expiring in
		// two hours, also for namesA
		"b": fqdnTestcase{
			Serial:       "b",
			Names:        namesA,
			ExpectedHash: expectedHashA,
			Issued:       now.Add(time.Hour),
			Expires:      now.Add(time.Hour * 2).UTC(),
		},
		// One test case with serial "c", issued one hour from now and expiring in
		// two hours, for namesB
		"c": fqdnTestcase{
			Serial:       "c",
			Names:        namesB,
			ExpectedHash: expectedHashB,
			Issued:       now.Add(time.Hour),
			Expires:      now.Add(time.Hour * 2).UTC(),
		},
		// One test case with serial "d", issued five hours in the past and expiring
		// in two hours from now, with namesC
		"d": fqdnTestcase{
			Serial:       "d",
			Names:        namesC,
			ExpectedHash: expectedHashC,
			Issued:       now.Add(-5 * time.Hour),
			Expires:      now.Add(time.Hour * 2).UTC(),
		},
	}

	for _, tc := range testcases {
		tx, err := db.Begin()
		test.AssertNotError(t, err, "Failed to open transaction")
		err = addFQDNSet(tx, tc.Names, tc.Serial, tc.Issued, tc.Expires)
		test.AssertNotError(t, err, fmt.Sprintf("Failed to add fqdnSet for %#v", tc))
		test.AssertNotError(t, tx.Commit(), "Failed to commit transaction")
	}

	return testcases
}

func TestGetFQDNSetsBySerials(t *testing.T) {
	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	// Add the test fqdn sets
	testcases := setupFQDNSets(t, sa.dbMap, fc)

	// Asking for the fqdnSets for no serials should produce an error since this
	// is not expected in normal conditions
	fqdnSets, err := sa.getFQDNSetsBySerials([]string{})
	test.AssertError(t, err, "No error calling getFQDNSetsBySerials for empty serials")
	test.AssertEquals(t, len(fqdnSets), 0)

	// Asking for the fqdnSets for serials that don't exist should return nothing
	fqdnSets, err = sa.getFQDNSetsBySerials([]string{"this", "doesn't", "exist"})
	test.AssertNotError(t, err, "Error calling getFQDNSetsBySerials for non-existent serials")
	test.AssertEquals(t, len(fqdnSets), 0)

	// Asking for the fqdnSets for serial "a" should return the expectedHashA hash
	fqdnSets, err = sa.getFQDNSetsBySerials([]string{"a"})
	test.AssertNotError(t, err, "Error calling getFQDNSetsBySerials for serial \"a\"")
	test.AssertEquals(t, len(fqdnSets), 1)
	test.AssertEquals(t, string(fqdnSets[0]), string(testcases["a"].ExpectedHash))

	// Asking for the fqdnSets for serial "b" should return the expectedHashA hash
	// because cert "b" has namesA subjects
	fqdnSets, err = sa.getFQDNSetsBySerials([]string{"b"})
	test.AssertNotError(t, err, "Error calling getFQDNSetsBySerials for serial \"b\"")
	test.AssertEquals(t, len(fqdnSets), 1)
	test.AssertEquals(t, string(fqdnSets[0]), string(testcases["b"].ExpectedHash))

	// Asking for the fqdnSets for serial "d" should return the expectedHashC hash
	// because cert "d" has namesC subjects
	fqdnSets, err = sa.getFQDNSetsBySerials([]string{"d"})
	test.AssertNotError(t, err, "Error calling getFQDNSetsBySerials for serial \"d\"")
	test.AssertEquals(t, len(fqdnSets), 1)
	test.AssertEquals(t, string(fqdnSets[0]), string(testcases["d"].ExpectedHash))

	// Asking for the fqdnSets for serial "c" should return the expectedHashB hash
	// because cert "c" has namesB subjects
	fqdnSets, err = sa.getFQDNSetsBySerials([]string{"c"})
	test.AssertNotError(t, err, "Error calling getFQDNSetsBySerials for serial \"c\"")
	test.AssertEquals(t, len(fqdnSets), 1)
	test.AssertEquals(t, string(fqdnSets[0]), string(testcases["c"].ExpectedHash))

	// Asking for the fqdnSets for serial "a", "b", "c" and "made up" should return
	// the three expected hashes - two expectedHashA (for "a" and "b"), one
	// expectedHashB (for "c")
	expectedHashes := map[string]int{
		string(testcases["a"].ExpectedHash): 2,
		string(testcases["c"].ExpectedHash): 1,
	}
	fqdnSets, err = sa.getFQDNSetsBySerials([]string{"a", "b", "c", "made up"})
	test.AssertNotError(t, err, "Error calling getFQDNSetsBySerials for serial \"a\", \"b\", \"c\", \"made up\"")

	for _, setHash := range fqdnSets {
		setHashKey := string(setHash)
		if _, present := expectedHashes[setHashKey]; !present {
			t.Errorf("Unexpected setHash in results: %#v", setHash)
		}
		expectedHashes[setHashKey]--
		if expectedHashes[setHashKey] <= 0 {
			delete(expectedHashes, setHashKey)
		}
	}
	if len(expectedHashes) != 0 {
		t.Errorf("Some expected setHashes were not observed: %#v", expectedHashes)
	}
}

func TestGetNewIssuancesByFQDNSet(t *testing.T) {
	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	// Add the test fqdn sets
	testcases := setupFQDNSets(t, sa.dbMap, fc)

	// Use one hour ago as the earliest cut off
	earliest := fc.Now().Add(-time.Hour)

	// Calling getNewIssuancesByFQDNSet with an empty FQDNSet should error
	count, err := sa.getNewIssuancesByFQDNSet(nil, earliest)
	test.AssertError(t, err, "No error calling getNewIssuancesByFQDNSet for empty fqdn set")
	test.AssertEquals(t, count, -1)

	// Calling getNewIssuancesByFQDNSet with FQDNSet hashes that don't exist
	// should return 0
	count, err = sa.getNewIssuancesByFQDNSet([]setHash{setHash{0xC0, 0xFF, 0xEE}, setHash{0x13, 0x37}}, earliest)
	test.AssertNotError(t, err, "Error calling getNewIssuancesByFQDNSet for non-existent set hashes")
	test.AssertEquals(t, count, 0)

	// Calling getNewIssuancesByFQDNSet with the "a" expected hash should return
	// 1, since both testcase "b" was a renewal of testcase "a"
	count, err = sa.getNewIssuancesByFQDNSet([]setHash{testcases["a"].ExpectedHash}, earliest)
	test.AssertNotError(t, err, "Error calling getNewIssuancesByFQDNSet for testcase a")
	test.AssertEquals(t, count, 1)

	// Calling getNewIssuancesByFQDNSet with the "c" expected hash should return
	// 1, since there is only one issuance for this sethash
	count, err = sa.getNewIssuancesByFQDNSet([]setHash{testcases["c"].ExpectedHash}, earliest)
	test.AssertNotError(t, err, "Error calling getNewIssuancesByFQDNSet for testcase c")
	test.AssertEquals(t, count, 1)

	// Calling getNewIssuancesByFQDNSet with the "c" and "d" expected hashes should return
	// only 1, since there is only one issuance for the provided set hashes that
	// is within the earliest window. The issuance for "d" was too far in the past
	// to be counted
	count, err = sa.getNewIssuancesByFQDNSet([]setHash{testcases["c"].ExpectedHash, testcases["d"].ExpectedHash}, earliest)
	test.AssertNotError(t, err, "Error calling getNewIssuancesByFQDNSet for testcase c and d")
	test.AssertEquals(t, count, 1)

	// But by moving the earliest point behind the "d" issuance, we should now get a count of 2
	count, err = sa.getNewIssuancesByFQDNSet([]setHash{testcases["c"].ExpectedHash, testcases["d"].ExpectedHash}, earliest.Add(-6*time.Hour))
	test.AssertNotError(t, err, "Error calling getNewIssuancesByFQDNSet for testcase c and d with adjusted earliest")
	test.AssertEquals(t, count, 2)
}

func TestNewOrder(t *testing.T) {
	// Only run under test/config-next config where 20170731115209_AddOrders.sql
	// has been applied
	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		return
	}

	sa, _, cleanup := initSA(t)
	defer cleanup()

	// Create a test registration to reference
	reg, err := sa.NewRegistration(ctx, core.Registration{
		Key:       &jose.JSONWebKey{Key: &rsa.PublicKey{N: big.NewInt(1), E: 1}},
		InitialIP: net.ParseIP("42.42.42.42"),
	})
	test.AssertNotError(t, err, "Couldn't create test registration")

	i := int64(1)
	status := string(core.StatusPending)
	order, err := sa.NewOrder(context.Background(), &corepb.Order{
		RegistrationID: &reg.ID,
		Expires:        &i,
		Names:          []string{"example.com", "just.another.example.com"},
		Authorizations: []string{"a", "b", "c"},
		Status:         &status,
	})
	test.AssertNotError(t, err, "sa.NewOrder failed")
	test.AssertEquals(t, *order.Id, int64(1))

	var authzIDs []string
	_, err = sa.dbMap.Select(&authzIDs, "SELECT authzID FROM orderToAuthz WHERE orderID = ?;", *order.Id)
	test.AssertNotError(t, err, "Failed to count orderToAuthz entries")
	test.AssertEquals(t, len(authzIDs), 3)
	test.AssertDeepEquals(t, authzIDs, []string{"a", "b", "c"})

	names, err := sa.namesForOrder(*order.Id)
	test.AssertNotError(t, err, "namesForOrder errored")
	test.AssertEquals(t, len(names), 2)
	test.AssertDeepEquals(t, names, []string{"com.example", "com.example.another.just"})
}

func TestSetOrderProcessing(t *testing.T) {
	// Only run under test/config-next config where 20170731115209_AddOrders.sql
	// has been applied
	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		return
	}

	sa, _, cleanup := initSA(t)
	defer cleanup()

	// Create a test registration to reference
	reg, err := sa.NewRegistration(ctx, core.Registration{
		Key:       &jose.JSONWebKey{Key: &rsa.PublicKey{N: big.NewInt(1), E: 1}},
		InitialIP: net.ParseIP("42.42.42.42"),
	})
	test.AssertNotError(t, err, "Couldn't create test registration")

	i := int64(1337)
	status := string(core.StatusPending)
	order := &corepb.Order{
		RegistrationID: &reg.ID,
		Expires:        &i,
		Names:          []string{"example.com"},
		Authorizations: []string{"a", "b", "c"},
		Status:         &status,
	}

	// Add a new order in pending status with no certificate serial
	order, err = sa.NewOrder(context.Background(), order)
	test.AssertNotError(t, err, "NewOrder failed")

	// Set the order to be processing
	err = sa.SetOrderProcessing(context.Background(), order)
	test.AssertNotError(t, err, "SetOrderProcessing failed")

	// Read the order by ID from the DB to check the status was correctly updated
	// to processing
	updatedOrder, err := sa.GetOrder(
		context.Background(),
		&sapb.OrderRequest{Id: order.Id})
	test.AssertNotError(t, err, "GetOrder failed")
	test.AssertEquals(t, *updatedOrder.Status, string(core.StatusProcessing))
}

func TestFinalizeOrder(t *testing.T) {
	// Only run under test/config-next config where 20170731115209_AddOrders.sql
	// has been applied
	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		return
	}

	sa, _, cleanup := initSA(t)
	defer cleanup()

	// Create a test registration to reference
	reg, err := sa.NewRegistration(ctx, core.Registration{
		Key:       &jose.JSONWebKey{Key: &rsa.PublicKey{N: big.NewInt(1), E: 1}},
		InitialIP: net.ParseIP("42.42.42.42"),
	})
	test.AssertNotError(t, err, "Couldn't create test registration")

	i := int64(1337)
	status := string(core.StatusProcessing)
	order := &corepb.Order{
		RegistrationID: &reg.ID,
		Expires:        &i,
		Names:          []string{"example.com"},
		Authorizations: []string{"a", "b", "c"},
		Status:         &status,
	}

	// Add a new order in processing status with an empty certificate serial
	order, err = sa.NewOrder(context.Background(), order)
	test.AssertNotError(t, err, "NewOrder failed")

	// Finalize the order with a certificate serial
	serial := "eat.serial.for.breakfast"
	order.CertificateSerial = &serial
	err = sa.FinalizeOrder(context.Background(), order)
	test.AssertNotError(t, err, "FinalizeOrder failed")

	// Read the order by ID from the DB to check the certificate serial and status
	// was correctly updated
	updatedOrder, err := sa.GetOrder(
		context.Background(),
		&sapb.OrderRequest{Id: order.Id})
	test.AssertNotError(t, err, "GetOrder failed")
	test.AssertEquals(t, *updatedOrder.CertificateSerial, serial)
	test.AssertEquals(t, *updatedOrder.Status, string(core.StatusValid))
}

func TestOrder(t *testing.T) {
	// Only run under test/config-next config where 20170731115209_AddOrders.sql
	// has been applied
	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		return
	}

	sa, _, cleanup := initSA(t)
	defer cleanup()

	// Create a test registration to reference
	reg, err := sa.NewRegistration(ctx, core.Registration{
		Key:       &jose.JSONWebKey{Key: &rsa.PublicKey{N: big.NewInt(1), E: 1}},
		InitialIP: net.ParseIP("42.42.42.42"),
	})
	test.AssertNotError(t, err, "Couldn't create test registration")

	expires := time.Now().Truncate(time.Second).UnixNano()
	status := string(core.StatusPending)
	empty := ""
	order, err := sa.NewOrder(context.Background(), &corepb.Order{
		RegistrationID:    &reg.ID,
		Expires:           &expires,
		Names:             []string{"example.com"},
		Authorizations:    []string{"a"},
		Status:            &status,
		CertificateSerial: &empty,
	})
	test.AssertNotError(t, err, "sa.NewOrder failed")
	test.AssertEquals(t, *order.Id, int64(1))

	storedOrder, err := sa.GetOrder(context.Background(), &sapb.OrderRequest{Id: order.Id})
	test.AssertNotError(t, err, "sa.Order failed")
	test.AssertDeepEquals(t, storedOrder, order)
}

func TestGetOrderAuthorizations(t *testing.T) {
	// Only run under test/config-next config where 20170731115209_AddOrders.sql
	// has been applied
	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		return
	}

	sa, _, cleanup := initSA(t)
	defer cleanup()

	// Create a throw away registration
	reg := satest.CreateWorkingRegistration(t, sa)

	// Create and finalize an authz for the throw-away reg and "example.com"
	authz := CreateDomainAuthWithRegID(t, "example.com", sa, reg.ID)
	exp := sa.clk.Now().Add(time.Hour * 24 * 7)
	authz.Expires = &exp
	authz.Status = "valid"
	err := sa.FinalizeAuthorization(ctx, authz)
	test.AssertNotError(t, err, "Couldn't create final authz with ID "+authz.ID)

	// Now create a new order that references the above authorization
	i := time.Now().Truncate(time.Second).UnixNano()
	status := string(core.StatusPending)
	order := &corepb.Order{
		RegistrationID: &reg.ID,
		Expires:        &i,
		Names:          []string{"example.com"},
		Authorizations: []string{authz.ID},
		Status:         &status,
	}
	order, err = sa.NewOrder(context.Background(), order)
	test.AssertNotError(t, err, "AddOrder failed")

	// Now fetch the order authorizations for the order we added for the
	// throw-away reg
	authzMap, err := sa.GetOrderAuthorizations(context.Background(), &sapb.GetOrderAuthorizationsRequest{
		Id:     order.Id,
		AcctID: &reg.ID,
	})
	// It should not fail and one valid authorization for the example.com domain
	// should be present with ID and status equal to the authz we created earlier.
	test.AssertNotError(t, err, "GetOrderAuthorizations failed")
	test.AssertNotNil(t, authzMap, "GetOrderAuthorizations result was nil")
	test.AssertEquals(t, len(authzMap), 1)
	test.AssertNotNil(t, authzMap["example.com"], "Authz for example.com was nil")
	test.AssertEquals(t, authzMap["example.com"].ID, authz.ID)
	test.AssertEquals(t, string(authzMap["example.com"].Status), "valid")

	// Getting the order authorizations for an order that doesn't exist should return nothing
	missingID := int64(0xC0FFEEEEEEE)
	authzMap, err = sa.GetOrderAuthorizations(context.Background(), &sapb.GetOrderAuthorizationsRequest{
		Id:     &missingID,
		AcctID: &reg.ID,
	})
	test.AssertNotError(t, err, "GetOrderAuthorizations for non-existent order errored")
	test.AssertEquals(t, len(authzMap), 0)

	// Getting the order authorizations for an order that does exist, but for the
	// wrong acct ID should return nothing
	wrongAcctID := int64(0xDEADDA7ABA5E)
	authzMap, err = sa.GetOrderAuthorizations(context.Background(), &sapb.GetOrderAuthorizationsRequest{
		Id:     order.Id,
		AcctID: &wrongAcctID,
	})
	test.AssertNotError(t, err, "GetOrderAuthorizations for existent order, wrong acctID errored")
	test.AssertEquals(t, len(authzMap), 0)
}

// TestGetAuthorizationNoRows ensures that the GetAuthorization function returns
// the correct error when there are no results for the provided ID.
func TestGetAuthorizationNoRows(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()

	// An empty authz ID should result in `sql.ErrNoRows`
	_, err := sa.GetAuthorization(ctx, "")
	test.AssertError(t, err, "Didn't get an error looking up empty authz ID")
	test.Assert(t, berrors.Is(err, berrors.NotFound), "GetAuthorization did not return a berrors.NotFound error")
}

func TestGetAuthorizations(t *testing.T) {
	sa, fc, cleanup := initSA(t)
	defer cleanup()

	reg := satest.CreateWorkingRegistration(t, sa)
	exp := fc.Now().AddDate(0, 0, 1)
	pa := core.Authorization{RegistrationID: reg.ID, Identifier: core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "a"}, Status: core.StatusPending, Expires: &exp, Combinations: [][]int{[]int{0, 1}}}

	paA, err := sa.NewPendingAuthorization(ctx, pa)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	test.Assert(t, paA.ID != "", "ID shouldn't be blank")

	pa.Identifier.Value = "b"
	paB, err := sa.NewPendingAuthorization(ctx, pa)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	test.Assert(t, paB.ID != "", "ID shouldn't be blank")

	paB.Status = core.StatusValid
	err = sa.FinalizeAuthorization(ctx, paB)
	test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+paB.ID)

	now := fc.Now().UnixNano()
	authz, err := sa.GetAuthorizations(context.Background(), &sapb.GetAuthorizationsRequest{
		RegistrationID: &reg.ID,
		Domains:        []string{"a", "b"},
		Now:            &now,
	})
	test.AssertNotError(t, err, "sa.GetAuthorizations failed")
	test.AssertEquals(t, len(authz.Authz), 2)
	authz, err = sa.GetAuthorizations(context.Background(), &sapb.GetAuthorizationsRequest{
		RegistrationID: &reg.ID,
		Domains:        []string{"a", "b", "c"},
		Now:            &now,
	})
	test.AssertNotError(t, err, "sa.GetAuthorizations failed")
	test.AssertEquals(t, len(authz.Authz), 2)
}

func TestAddPendingAuthorizations(t *testing.T) {
	sa, fc, cleanup := initSA(t)
	defer cleanup()

	reg := satest.CreateWorkingRegistration(t, sa)
	expires := fc.Now().Add(time.Hour).UnixNano()
	identA := `a`
	identB := `a`
	combo := []byte(`[[0]]`)
	status := string(core.StatusPending)
	empty := ""
	authz := []*corepb.Authorization{
		&corepb.Authorization{
			Id:             &empty,
			Identifier:     &identA,
			RegistrationID: &reg.ID,
			Status:         &status,
			Expires:        &expires,
			Combinations:   combo,
		},
		&corepb.Authorization{
			Id:             &empty,
			Identifier:     &identB,
			RegistrationID: &reg.ID,
			Status:         &status,
			Expires:        &expires,
			Combinations:   combo,
		},
	}

	ids, err := sa.AddPendingAuthorizations(context.Background(), &sapb.AddPendingAuthorizationsRequest{Authz: authz})
	test.AssertNotError(t, err, "sa.AddPendingAuthorizations failed")
	test.AssertEquals(t, len(ids.Ids), 2)

	for _, id := range ids.Ids {
		_, err := sa.GetAuthorization(context.Background(), id)
		test.AssertNotError(t, err, "sa.GetAuthorization failed")
	}
}

func TestCountPendingOrders(t *testing.T) {
	// Only run under test/config-next config where 20170731115209_AddOrders.sql
	// has been applied
	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		return
	}

	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	expires := fc.Now().Add(time.Hour).UnixNano()
	status := string(core.StatusPending)

	// Counting pending orders for a reg ID that doesn't exist should return 0
	count, err := sa.CountPendingOrders(ctx, 12345)
	test.AssertNotError(t, err, "Couldn't count pending authorizations for fake reg ID")
	test.AssertEquals(t, count, 0)

	// Add one pending order
	_, err = sa.NewOrder(ctx, &corepb.Order{
		RegistrationID: &reg.ID,
		Expires:        &expires,
		Names:          []string{"example.com"},
		Authorizations: []string{"abcd"},
		Status:         &status,
	})
	test.AssertNotError(t, err, "Couldn't create new pending order")

	// We expect there to be a count of one for this reg ID
	count, err = sa.CountPendingOrders(ctx, reg.ID)
	test.AssertNotError(t, err, "Couldn't count pending authorizations")
	test.AssertEquals(t, count, 1)

	// Create a pending order that expired an hour ago
	expires = fc.Now().Add(-time.Hour).UnixNano()
	_, err = sa.NewOrder(ctx, &corepb.Order{
		RegistrationID: &reg.ID,
		Expires:        &expires,
		Names:          []string{"example.com"},
		Authorizations: []string{"abcd"},
		Status:         &status,
	})
	test.AssertNotError(t, err, "Couldn't create new expired pending order")

	// We still expect there to be a count of one for this reg ID since the order
	// added above is expired
	count, err = sa.CountPendingOrders(ctx, reg.ID)
	test.AssertNotError(t, err, "Couldn't count pending authorizations")
	test.AssertEquals(t, count, 1)

	// Create a non-pending order
	expires = fc.Now().Add(time.Hour).UnixNano()
	status = "off-the-hook"
	_, err = sa.NewOrder(ctx, &corepb.Order{
		RegistrationID: &reg.ID,
		Expires:        &expires,
		Names:          []string{"example.com"},
		Authorizations: []string{"abcd"},
		Status:         &status,
	})
	test.AssertNotError(t, err, "Couldn't create new non-pending order")

	// We still expect there to be a count of one for this reg ID since the order
	// added above is not pending
	count, err = sa.CountPendingOrders(ctx, reg.ID)
	test.AssertNotError(t, err, "Couldn't count pending authorizations")
	test.AssertEquals(t, count, 1)

	// If the clock is advanced by two hours we expect the count to return to
	// 0 for this reg ID since all of the pending orders we created will have
	// expired.
	fc.Add(2 * time.Hour)
	count, err = sa.CountPendingOrders(ctx, reg.ID)
	test.AssertNotError(t, err, "Couldn't count pending authorizations")
	test.AssertEquals(t, count, 0)
}

func TestGetOrderForNames(t *testing.T) {
	// Only run under test/config-next config where required migrations
	// have been applied
	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		return
	}

	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	// Give the order we create a short lifetime
	orderLifetime := time.Hour
	expires := fc.Now().Add(orderLifetime).UnixNano()

	// Create two test registrations to associate with orders
	regA, err := sa.NewRegistration(ctx, core.Registration{
		Key:       satest.GoodJWK(),
		InitialIP: net.ParseIP("42.42.42.42"),
	})
	test.AssertNotError(t, err, "Couldn't create test registration")

	ctx := context.Background()
	status := string(core.StatusPending)
	names := []string{"example.com", "just.another.example.com"}

	// Call GetOrderForNames for a set of names we haven't created an order for
	// yet
	result, err := sa.GetOrderForNames(ctx, &sapb.GetOrderForNamesRequest{
		AcctID: &regA.ID,
		Names:  names,
	})
	// We expect the result to return an error
	test.AssertError(t, err, "sa.GetOrderForNames did not return an error for an empty result")
	// The error should be a notfound error
	test.AssertEquals(t, berrors.Is(err, berrors.NotFound), true)
	// The result should be nil
	test.Assert(t, result == nil, "sa.GetOrderForNames for non-existent order returned non-nil result")

	// Add a new order for a set of names
	order, err := sa.NewOrder(ctx, &corepb.Order{
		RegistrationID: &regA.ID,
		Expires:        &expires,
		Status:         &status,
		Authorizations: []string{"a", "b", "c"},
		Names:          names,
	})
	// It shouldn't error
	test.AssertNotError(t, err, "sa.NewOrder failed")
	// The order ID shouldn't be nil
	test.AssertNotNil(t, *order.Id, "NewOrder returned with a nil Id")

	// Call GetOrderForNames with the same account ID and set of names as the
	// above NewOrder call
	result, err = sa.GetOrderForNames(ctx, &sapb.GetOrderForNamesRequest{
		AcctID: &regA.ID,
		Names:  names,
	})
	// It shouldn't error
	test.AssertNotError(t, err, "sa.GetOrderForNames failed")
	// The order returned should have the same ID as the order we created above
	test.AssertNotNil(t, result, "Returned order was nil")
	test.AssertEquals(t, *result.Id, *order.Id)

	// Call GetOrderForNames with a different account ID from the NewOrder call
	regB := int64(1337)
	result, err = sa.GetOrderForNames(ctx, &sapb.GetOrderForNamesRequest{
		AcctID: &regB,
		Names:  names,
	})
	// It should error
	test.AssertError(t, err, "sa.GetOrderForNames did not return an error for an empty result")
	// The error should be a notfound error
	test.AssertEquals(t, berrors.Is(err, berrors.NotFound), true)
	// The result should be nil
	test.Assert(t, result == nil, "sa.GetOrderForNames for diff AcctID returned non-nil result")

	// Advance the clock beyond the initial order's lifetime
	fc.Add(2 * orderLifetime)

	// Call GetOrderForNames again with the same account ID and set of names as
	// the initial NewOrder call
	result, err = sa.GetOrderForNames(ctx, &sapb.GetOrderForNamesRequest{
		AcctID: &regA.ID,
		Names:  names,
	})
	// It should error since there is no result
	test.AssertError(t, err, "sa.GetOrderForNames did not return an error for an empty result")
	// The error should be a notfound error
	test.AssertEquals(t, berrors.Is(err, berrors.NotFound), true)
	// The result should be nil because the initial order expired & we don't want
	// to return expired orders
	test.Assert(t, result == nil, "sa.GetOrderForNames returned non-nil result for expired order case")

	// Add a fresh order for a different of names. Put its status as Processing so
	// we can finalize it
	expires = fc.Now().Add(orderLifetime).UnixNano()
	statusProcessing := string(core.StatusProcessing)
	names = []string{"zombo.com", "welcome.to.zombo.com"}
	order, err = sa.NewOrder(ctx, &corepb.Order{
		RegistrationID: &regA.ID,
		Expires:        &expires,
		Status:         &statusProcessing,
		Authorizations: []string{"a", "b", "c"},
		Names:          names,
	})
	// It shouldn't error
	test.AssertNotError(t, err, "sa.NewOrder failed")
	// The order ID shouldn't be nil
	test.AssertNotNil(t, *order.Id, "NewOrder returned with a nil Id")

	// Finalize the order
	serial := "cinnamon toast crunch"
	order.CertificateSerial = &serial
	err = sa.FinalizeOrder(ctx, order)
	test.AssertNotError(t, err, "sa.FinalizeOrder failed")

	// Call GetOrderForNames with the same account ID and set of names as
	// the above NewOrder call
	result, err = sa.GetOrderForNames(ctx, &sapb.GetOrderForNamesRequest{
		AcctID: &regA.ID,
		Names:  names,
	})
	// It should error since there is no result
	test.AssertError(t, err, "sa.GetOrderForNames did not return an error for an empty result")
	// The error should be a notfound error
	test.AssertEquals(t, berrors.Is(err, berrors.NotFound), true)
	// The result should be nil because the one matching order has been finalized
	// already
	test.Assert(t, result == nil, "sa.GetOrderForNames returned non-nil result for finalized order case")
}

func TestUpdatePendingAuthorizationInvalidOrder(t *testing.T) {
	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		return
	}

	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	expires := fc.Now().Add(time.Hour)
	ctx := context.Background()

	// Create a registration to work with
	reg := satest.CreateWorkingRegistration(t, sa)

	// Create a pending authz, not associated with any orders
	authz := core.Authorization{
		RegistrationID: reg.ID,
		Expires:        &expires,
		Status:         core.StatusPending,
	}
	pendingAuthz, err := sa.NewPendingAuthorization(ctx, authz)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")

	// Update the pending authz to be invalid. This shouldn't error.
	pendingAuthz.Status = core.StatusInvalid
	err = sa.FinalizeAuthorization(ctx, pendingAuthz)
	test.AssertNotError(t, err, "Couldn't finalize legacy pending authz to invalid")

	// Create a pending authz that will be associated with an order
	authz = core.Authorization{
		RegistrationID: reg.ID,
		Expires:        &expires,
		Status:         core.StatusPending,
	}
	pendingAuthz, err = sa.NewPendingAuthorization(ctx, authz)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")

	// Add a new order that references the above pending authz
	status := string(core.StatusPending)
	expiresNano := expires.UnixNano()
	order, err := sa.NewOrder(ctx, &corepb.Order{
		RegistrationID: &reg.ID,
		Expires:        &expiresNano,
		Status:         &status,
		Authorizations: []string{pendingAuthz.ID},
		Names:          []string{"your.order.is.up"},
	})
	// It shouldn't error
	test.AssertNotError(t, err, "sa.NewOrder failed")
	// The order ID shouldn't be nil
	test.AssertNotNil(t, *order.Id, "NewOrder returned with a nil Id")
	// The order should be pending
	test.AssertEquals(t, *order.Status, string(core.StatusPending))
	// The order should have one authz with the correct ID
	test.AssertEquals(t, len(order.Authorizations), 1)
	test.AssertEquals(t, order.Authorizations[0], pendingAuthz.ID)

	// Now finalize the authz to an invalid status.
	pendingAuthz.Status = core.StatusInvalid
	err = sa.FinalizeAuthorization(ctx, pendingAuthz)
	test.AssertNotError(t, err, "Couldn't finalize pending authz associated with order to invalid")

	// Fetch the order to get its updated status
	updatedOrder, err := sa.GetOrder(
		context.Background(),
		&sapb.OrderRequest{Id: order.Id})
	test.AssertNotError(t, err, "GetOrder failed")
	// We expect the updated order status to be invalid
	test.AssertEquals(t, *updatedOrder.Status, string(core.StatusInvalid))
}
