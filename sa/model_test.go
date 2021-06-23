package sa

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/db"
	"github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test/vars"
	jose "gopkg.in/square/go-jose.v2"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/test"
)

func TestModelToRegistrationNilContact(t *testing.T) {
	reg, err := modelToRegistration(&regModel{
		Key:     []byte(`{"kty":"RSA","n":"AQAB","e":"AQAB"}`),
		Contact: nil,
	})
	if err != nil {
		t.Errorf("Got error from modelToRegistration: %s", err)
	}
	if reg.Contact == nil {
		t.Errorf("Expected non-nil Contact field, got %#v", reg.Contact)
	}
	if len(*reg.Contact) != 0 {
		t.Errorf("Expected empty Contact field, got %#v", reg.Contact)
	}
}

// TestModelToRegistrationBadJSON tests that converting a model with an invalid
// JWK JSON produces the expected bad JSON error.
func TestModelToRegistrationBadJSON(t *testing.T) {
	badJSON := []byte(`{`)
	_, err := modelToRegistration(&regModel{
		Key: badJSON,
	})
	test.AssertError(t, err, "expected error from truncated reg model key")
	var badJSONErr errBadJSON
	test.AssertErrorWraps(t, err, &badJSONErr)
	test.AssertEquals(t, string(badJSONErr.json), string(badJSON))
}

func TestModelToRegistrationNonNilContact(t *testing.T) {
	reg, err := modelToRegistration(&regModel{
		Key:     []byte(`{"kty":"RSA","n":"AQAB","e":"AQAB"}`),
		Contact: []string{},
	})
	if err != nil {
		t.Errorf("Got error from modelToRegistration: %s", err)
	}
	if reg.Contact == nil {
		t.Errorf("Expected non-nil Contact field, got %#v", reg.Contact)
	}
	if len(*reg.Contact) != 0 {
		t.Errorf("Expected empty Contact field, got %#v", reg.Contact)
	}
}

func TestAuthzModel(t *testing.T) {
	authzPB := &corepb.Authorization{
		Id:             "1",
		Identifier:     "example.com",
		RegistrationID: 1,
		Status:         string(core.StatusValid),
		Expires:        1234,
		Challenges: []*corepb.Challenge{
			{
				Type:      string(core.ChallengeTypeHTTP01),
				Status:    string(core.StatusValid),
				Token:     "MTIz",
				Validated: 1234,
				Validationrecords: []*corepb.ValidationRecord{
					{
						Hostname:          "hostname",
						Port:              "port",
						AddressUsed:       []byte("1.2.3.4"),
						Url:               "url",
						AddressesResolved: [][]byte{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}},
						AddressesTried:    [][]byte{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}},
					},
				},
			},
		},
	}

	model, err := authzPBToModel(authzPB)
	test.AssertNotError(t, err, "authzPBToModel failed")

	authzPBOut, err := modelToAuthzPB(*model)
	test.AssertNotError(t, err, "modelToAuthzPB failed")
	test.AssertDeepEquals(t, authzPB.Challenges, authzPBOut.Challenges)

	validationErr := probs.ConnectionFailure("weewoo")
	authzPB.Challenges[0].Status = string(core.StatusInvalid)
	authzPB.Challenges[0].Error, err = grpc.ProblemDetailsToPB(validationErr)
	test.AssertNotError(t, err, "grpc.ProblemDetailsToPB failed")
	model, err = authzPBToModel(authzPB)
	test.AssertNotError(t, err, "authzPBToModel failed")

	authzPBOut, err = modelToAuthzPB(*model)
	test.AssertNotError(t, err, "modelToAuthzPB failed")
	test.AssertDeepEquals(t, authzPB.Challenges, authzPBOut.Challenges)

	authzPB = &corepb.Authorization{
		Id:             "1",
		Identifier:     "example.com",
		RegistrationID: 1,
		Status:         string(core.StatusInvalid),
		Expires:        1234,
		Challenges: []*corepb.Challenge{
			{
				Type:   string(core.ChallengeTypeHTTP01),
				Status: string(core.StatusInvalid),
				Token:  "MTIz",
				Validationrecords: []*corepb.ValidationRecord{
					{
						Hostname:          "hostname",
						Port:              "port",
						AddressUsed:       []byte("1.2.3.4"),
						Url:               "url",
						AddressesResolved: [][]byte{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}},
						AddressesTried:    [][]byte{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}},
					},
				},
			},
			{
				Type:   string(core.ChallengeTypeDNS01),
				Status: string(core.StatusInvalid),
				Token:  "MTIz",
				Validationrecords: []*corepb.ValidationRecord{
					{
						Hostname:          "hostname",
						Port:              "port",
						AddressUsed:       []byte("1.2.3.4"),
						Url:               "url",
						AddressesResolved: [][]byte{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}},
						AddressesTried:    [][]byte{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}},
					},
				},
			},
		},
	}
	_, err = authzPBToModel(authzPB)
	test.AssertError(t, err, "authzPBToModel didn't fail with multiple non-pending challenges")
}

// TestModelToChallengeBadJSON tests that converting a challenge model with an
// invalid validation error field or validation record field produces the
// expected bad JSON error.
func TestModelToChallengeBadJSON(t *testing.T) {
	badJSON := []byte(`{`)

	testCases := []struct {
		Name  string
		Model *challModel
	}{
		{
			Name: "Bad error field",
			Model: &challModel{
				Error: badJSON,
			},
		},
		{
			Name: "Bad validation record field",
			Model: &challModel{
				ValidationRecord: badJSON,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			_, err := modelToChallenge(tc.Model)
			test.AssertError(t, err, "expected error from modelToChallenge")
			var badJSONErr errBadJSON
			test.AssertErrorWraps(t, err, &badJSONErr)
			test.AssertEquals(t, string(badJSONErr.json), string(badJSON))
		})
	}
}

// TestModelToOrderBADJSON tests that converting an order model with an invalid
// validation error JSON field to an Order produces the expected bad JSON error.
func TestModelToOrderBadJSON(t *testing.T) {
	badJSON := []byte(`{`)
	_, err := modelToOrder(&orderModel{
		Error: badJSON,
	})
	test.AssertError(t, err, "expected error from modelToOrder")
	var badJSONErr errBadJSON
	test.AssertErrorWraps(t, err, &badJSONErr)
	test.AssertEquals(t, string(badJSONErr.json), string(badJSON))
}

// TestPopulateAttemptedFieldsBadJSON tests that populating a challenge from an
// authz2 model with an invalid validation error or an invalid validation record
// produces the expected bad JSON error.
func TestPopulateAttemptedFieldsBadJSON(t *testing.T) {
	badJSON := []byte(`{`)

	testCases := []struct {
		Name  string
		Model *authzModel
	}{
		{
			Name: "Bad validation error field",
			Model: &authzModel{
				ValidationError: badJSON,
			},
		},
		{
			Name: "Bad validation record field",
			Model: &authzModel{
				ValidationRecord: badJSON,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			err := populateAttemptedFields(*tc.Model, &corepb.Challenge{})
			test.AssertError(t, err, "expected error from populateAttemptedFields")
			var badJSONErr errBadJSON
			test.AssertErrorWraps(t, err, &badJSONErr)
			test.AssertEquals(t, string(badJSONErr.json), string(badJSON))
		})
	}
}

func TestCerficatesTableContainsDuplicateSerials(t *testing.T) {
	testCtx := setup(t)
	defer testCtx.cleanUp()

	serialString := core.SerialToString(big.NewInt(1337))

	// Register and insert a certificate with a serial of `1337`.
	testCtx.setupCertificate1337A(t)

	// This should return the certificate that we just inserted.
	_, err := SelectCertificate(testCtx.db, serialString)
	test.AssertNotError(t, err, "received an error for a valid query")

	// Register and insert a certificate with a serial of `1337` but for a
	// different hostname.
	testCtx.setupCertificate1337B(t)

	// With a duplicate being present, this should error.
	_, err = SelectCertificate(testCtx.db, serialString)
	test.AssertError(t, err, "should've received an error for multiple rows")
}

type testCtx struct {
	db      *db.WrappedMap
	ssa     core.StorageAdder
	cleanUp func()
}

func (c testCtx) registerCertificate(t *testing.T, emailRaw string, jsonKey []byte, regID int64) {
	var key jose.JSONWebKey
	err := json.Unmarshal(jsonKey, &key)
	test.AssertNotError(t, err, "Failed to unmarshal public JWK")

	var reg core.Registration
	email := "mailto:" + emailRaw
	reg = core.Registration{
		ID: regID,
		Contact: &[]string{
			email,
		},
		Key:       &key,
		InitialIP: net.ParseIP("127.0.0.1"),
	}
	ctx := context.Background()
	_, err = c.ssa.NewRegistration(ctx, reg)
	test.AssertNotError(t, err, "Couldn't complete registration")
}

func (ctx testCtx) insertCertificate(t *testing.T, hostname string, serial, regID int64) {
	serialBigInt := big.NewInt(serial)
	serialString := core.SerialToString(serialBigInt)

	fc := newFakeClock(t)

	rawCert := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "leet",
		},
		NotAfter:     fc.Now().Add(30 * 24 * time.Hour),
		DNSNames:     []string{hostname},
		SerialNumber: serialBigInt,
	}

	n := bigIntFromB64("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw==")
	e := intFromB64("AQAB")
	d := bigIntFromB64("bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ==")
	p := bigIntFromB64("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc=")
	q := bigIntFromB64("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc=")
	testKey := rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: e}, D: d, Primes: []*big.Int{p, q}}

	certDer, _ := x509.CreateCertificate(rand.Reader, &rawCert, &rawCert, &testKey.PublicKey, &testKey)
	cert := &core.Certificate{
		RegistrationID: regID,
		Serial:         serialString,
		Expires:        rawCert.NotAfter,
		DER:            certDer,
	}
	err := ctx.db.Insert(cert)
	test.AssertNotError(t, err, "Couldn't insert certificate")
}

// setupCertificate1337A registers and inserts a record into the `certificates`
// table with a domain of `1337.com`, `registrationID` of `1` and a `serial` of
// `1337`.
func (c testCtx) setupCertificate1337A(t *testing.T) {
	jsonKey := []byte(`
{
  "kty":"RSA",
  "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
  "e":"AQAB"
}`)
	c.registerCertificate(t, "test@example.com", jsonKey, 1)
	c.insertCertificate(t, "1337.com", 1337, 1)
}

// setupCertificate1337A registers and inserts a record into the `certificates`
// table with a domain of `1337.net`, `registrationID` of `1` and a `serial` of
// `1337`.
func (c testCtx) setupCertificate1337B(t *testing.T) {
	jsonKey := []byte(`
{
  "kty":"RSA",
  "n":"z8bp-jPtHt4lKBqepeKF28g_QAEOuEsCIou6sZ9ndsQsEjxEOQxQ0xNOQezsKa63eogw8YS3vzjUcPP5BJuVzfPfGd5NVUdT-vSSwxk3wvk_jtNqhrpcoG0elRPQfMVsQWmxCAXCVRz3xbcFI8GTe-syynG3l-g1IzYIIZVNI6jdljCZML1HOMTTW4f7uJJ8mM-08oQCeHbr5ejK7O2yMSSYxW03zY-Tj1iVEebROeMv6IEEJNFSS4yM-hLpNAqVuQxFGetwtwjDMC1Drs1dTWrPuUAAjKGrP151z1_dE74M5evpAhZUmpKv1hY-x85DC6N0hFPgowsanmTNNiV75w",
  "e":"AQAB"
}`)
	c.registerCertificate(t, "test@example.com", jsonKey, 1)
	c.insertCertificate(t, "1337.net", 1337, 1)
}

func setup(t *testing.T) testCtx {
	dbMap, err := NewDbMap(vars.DBConnSAFullPerms, DbSettings{})
	test.AssertNotError(t, err, "Couldn't create database connection")

	cleanUp := test.ResetSATestDatabase(t)
	fc := newFakeClock(t)

	ssa, err := NewSQLStorageAuthority(dbMap, fc, log, metrics.NoopRegisterer, 1)
	test.AssertNotError(t, err, "Unable to create SQLStorageAuthority")
	return testCtx{dbMap, ssa, cleanUp}
}

func bigIntFromB64(b64 string) *big.Int {
	bytes, _ := base64.URLEncoding.DecodeString(b64)
	x := big.NewInt(0)
	x.SetBytes(bytes)
	return x
}

func intFromB64(b64 string) int {
	return int(bigIntFromB64(b64).Int64())
}

func newFakeClock(t *testing.T) clock.FakeClock {
	const fakeTimeFormat = "2006-01-02T15:04:05.999999999Z"
	ft, err := time.Parse(fakeTimeFormat, fakeTimeFormat)
	test.AssertNotError(t, err, "Couldn't create fake clock")
	fc := clock.NewFake()
	fc.Set(ft.UTC())
	return fc
}
