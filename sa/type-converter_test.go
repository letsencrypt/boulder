package sa

import (
	"encoding/json"
	"testing"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/test"

	jose "gopkg.in/square/go-jose.v1"
)

const JWK1JSON = `{
  "kty": "RSA",
  "n": "vuc785P8lBj3fUxyZchF_uZw6WtbxcorqgTyq-qapF5lrO1U82Tp93rpXlmctj6fyFHBVVB5aXnUHJ7LZeVPod7Wnfl8p5OyhlHQHC8BnzdzCqCMKmWZNX5DtETDId0qzU7dPzh0LP0idt5buU7L9QNaabChw3nnaL47iu_1Di5Wp264p2TwACeedv2hfRDjDlJmaQXuS8Rtv9GnRWyC9JBu7XmGvGDziumnJH7Hyzh3VNu-kSPQD3vuAFgMZS6uUzOztCkT0fpOalZI6hqxtWLvXUMj-crXrn-Maavz8qRhpAyp5kcYk3jiHGgQIi7QSK2JIdRJ8APyX9HlmTN5AQ",
  "e": "AQAB"
}`

func TestAcmeIdentifier(t *testing.T) {
	tc := BoulderTypeConverter{}

	ai := core.AcmeIdentifier{Type: "data1", Value: "data2"}
	out := core.AcmeIdentifier{}

	marshaledI, err := tc.ToDb(ai)
	test.AssertNotError(t, err, "Could not ToDb")

	scanner, ok := tc.FromDb(&out)
	test.Assert(t, ok, "FromDb failed")
	if !ok {
		t.FailNow()
		return
	}

	marshaled := marshaledI.(string)
	err = scanner.Binder(&marshaled, &out)
	test.AssertNotError(t, err, "failed to scanner.Binder")
	test.AssertMarshaledEquals(t, ai, out)
}

func TestJsonWebKey(t *testing.T) {
	tc := BoulderTypeConverter{}

	var jwk, out jose.JsonWebKey
	err := json.Unmarshal([]byte(JWK1JSON), &jwk)
	if err != nil {
		t.Fatal(err)
	}

	marshaledI, err := tc.ToDb(jwk)
	test.AssertNotError(t, err, "Could not ToDb")

	scanner, ok := tc.FromDb(&out)
	test.Assert(t, ok, "FromDb failed")
	if !ok {
		t.FailNow()
		return
	}

	marshaled := marshaledI.(string)
	err = scanner.Binder(&marshaled, &out)
	test.AssertNotError(t, err, "failed to scanner.Binder")
	test.AssertMarshaledEquals(t, jwk, out)
}

func TestAcmeStatus(t *testing.T) {
	tc := BoulderTypeConverter{}

	var as, out core.AcmeStatus
	as = "core.AcmeStatus"

	marshaledI, err := tc.ToDb(as)
	test.AssertNotError(t, err, "Could not ToDb")

	scanner, ok := tc.FromDb(&out)
	test.Assert(t, ok, "FromDb failed")
	if !ok {
		t.FailNow()
		return
	}

	marshaled := marshaledI.(string)
	err = scanner.Binder(&marshaled, &out)
	test.AssertNotError(t, err, "failed to scanner.Binder")
	test.AssertMarshaledEquals(t, as, out)
}

func TestOCSPStatus(t *testing.T) {
	tc := BoulderTypeConverter{}

	var os, out core.OCSPStatus
	os = "core.OCSPStatus"

	marshaledI, err := tc.ToDb(os)
	test.AssertNotError(t, err, "Could not ToDb")

	scanner, ok := tc.FromDb(&out)
	test.Assert(t, ok, "FromDb failed")
	if !ok {
		t.FailNow()
		return
	}

	marshaled := marshaledI.(string)
	err = scanner.Binder(&marshaled, &out)
	test.AssertNotError(t, err, "failed to scanner.Binder")
	test.AssertMarshaledEquals(t, os, out)
}

func TestStringSlice(t *testing.T) {
	tc := BoulderTypeConverter{}
	var au, out []string

	marshaledI, err := tc.ToDb(au)
	test.AssertNotError(t, err, "Could not ToDb")

	scanner, ok := tc.FromDb(&out)
	test.Assert(t, ok, "FromDb failed")
	if !ok {
		t.FailNow()
		return
	}

	marshaled := marshaledI.(string)
	err = scanner.Binder(&marshaled, &out)
	test.AssertNotError(t, err, "failed to scanner.Binder")
	test.AssertMarshaledEquals(t, au, out)
}
