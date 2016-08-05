package grpc

import (
	"encoding/json"
	"net"
	"testing"

	"github.com/square/go-jose"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"
	vapb "github.com/letsencrypt/boulder/va/proto"
)

func TestAuthzMeta(t *testing.T) {
	authz := core.Authorization{ID: "asd", RegistrationID: 10}
	pb, err := authzMetaToPB(authz)
	test.AssertNotError(t, err, "authzMetaToPB failed")
	test.Assert(t, pb != nil, "return vapb.AuthzMeta is nill")
	test.Assert(t, pb.Id != nil, "Id field is nil")
	test.AssertEquals(t, *pb.Id, authz.ID)
	test.Assert(t, pb.RegID != nil, "RegistrationID field is nil")
	test.AssertEquals(t, *pb.RegID, authz.RegistrationID)

	recon, err := pbToAuthzMeta(pb)
	test.AssertNotError(t, err, "pbToAuthzMeta failed")
	test.AssertEquals(t, recon.ID, authz.ID)
	test.AssertEquals(t, recon.RegistrationID, authz.RegistrationID)

	_, err = pbToAuthzMeta(nil)
	test.AssertError(t, err, "pbToAuthzMeta did not fail")
	test.AssertEquals(t, err, ErrMissingParameters)
	_, err = pbToAuthzMeta(&vapb.AuthzMeta{})
	test.AssertError(t, err, "pbToAuthzMeta did not fail")
	test.AssertEquals(t, err, ErrMissingParameters)
	empty := ""
	one := int64(1)
	_, err = pbToAuthzMeta(&vapb.AuthzMeta{Id: &empty})
	test.AssertError(t, err, "pbToAuthzMeta did not fail")
	test.AssertEquals(t, err, ErrMissingParameters)
	_, err = pbToAuthzMeta(&vapb.AuthzMeta{RegID: &one})
	test.AssertError(t, err, "pbToAuthzMeta did not fail")
	test.AssertEquals(t, err, ErrMissingParameters)
}

const JWK1JSON = `{"kty":"RSA","n":"vuc785P8lBj3fUxyZchF_uZw6WtbxcorqgTyq-qapF5lrO1U82Tp93rpXlmctj6fyFHBVVB5aXnUHJ7LZeVPod7Wnfl8p5OyhlHQHC8BnzdzCqCMKmWZNX5DtETDId0qzU7dPzh0LP0idt5buU7L9QNaabChw3nnaL47iu_1Di5Wp264p2TwACeedv2hfRDjDlJmaQXuS8Rtv9GnRWyC9JBu7XmGvGDziumnJH7Hyzh3VNu-kSPQD3vuAFgMZS6uUzOztCkT0fpOalZI6hqxtWLvXUMj-crXrn-Maavz8qRhpAyp5kcYk3jiHGgQIi7QSK2JIdRJ8APyX9HlmTN5AQ","e":"AQAB"}`

func TestJWK(t *testing.T) {
	var jwk jose.JsonWebKey
	err := json.Unmarshal([]byte(JWK1JSON), &jwk)
	test.AssertNotError(t, err, "Failed to unmarshal test key")

	str, err := jwkToString(&jwk)
	test.AssertNotError(t, err, "jwkToString failed")
	test.AssertEquals(t, str, JWK1JSON)

	recon, err := stringToJWK(str)
	test.AssertNotError(t, err, "stringToJWK failed")
	test.AssertDeepEquals(t, recon.Key, jwk.Key)
}

func TestProblemDetails(t *testing.T) {
	pb, err := problemDetailsToPB(nil)
	test.AssertNotEquals(t, err, "problemDetailToPB failed")
	test.Assert(t, pb == nil, "Returned corepb.ProblemDetails is not nil")

	prob := &probs.ProblemDetails{Type: probs.TLSProblem, Detail: "asd", HTTPStatus: 200}
	pb, err = problemDetailsToPB(prob)
	test.AssertNotError(t, err, "problemDetailToPB failed")
	test.Assert(t, pb != nil, "return corepb.ProblemDetails is nill")
	test.AssertDeepEquals(t, *pb.ProblemType, string(prob.Type))
	test.AssertEquals(t, *pb.Detail, prob.Detail)
	test.AssertEquals(t, int(*pb.HttpStatus), prob.HTTPStatus)

	recon, err := pbToProblemDetails(pb)
	test.AssertNotError(t, err, "pbToProblemDetails failed")
	test.AssertDeepEquals(t, recon, prob)

	recon, err = pbToProblemDetails(nil)
	test.AssertNotError(t, err, "pbToProblemDetails failed")
	test.Assert(t, recon == nil, "Returned core.PRoblemDetails is not nil")
	_, err = pbToProblemDetails(&corepb.ProblemDetails{})
	test.AssertError(t, err, "pbToProblemDetails did not fail")
	test.AssertEquals(t, err, ErrMissingParameters)
	empty := ""
	_, err = pbToProblemDetails(&corepb.ProblemDetails{ProblemType: &empty})
	test.AssertError(t, err, "pbToProblemDetails did not fail")
	test.AssertEquals(t, err, ErrMissingParameters)
	_, err = pbToProblemDetails(&corepb.ProblemDetails{Detail: &empty})
	test.AssertError(t, err, "pbToProblemDetails did not fail")
	test.AssertEquals(t, err, ErrMissingParameters)
}

func TestVAChallenge(t *testing.T) {
	var jwk jose.JsonWebKey
	err := json.Unmarshal([]byte(JWK1JSON), &jwk)
	test.AssertNotError(t, err, "Failed to unmarshal test key")
	chall := core.Challenge{
		ID:     10,
		Type:   core.ChallengeTypeDNS01,
		Status: core.StatusPending,
		Token:  "asd",
		ProvidedKeyAuthorization: "keyauth",
	}

	pb, err := vaChallengeToPB(chall)
	test.AssertNotError(t, err, "vaChallengeToPB failed")
	test.Assert(t, pb != nil, "Returned corepb.Challenge is nil")

	recon, err := pbToVAChallenge(pb)
	test.AssertNotError(t, err, "pbToVAChallenge failed")
	test.AssertDeepEquals(t, recon, chall)

	_, err = pbToVAChallenge(nil)
	test.AssertError(t, err, "pbToVAChallenge did not fail")
	test.AssertEquals(t, err, ErrMissingParameters)
	_, err = pbToVAChallenge(&corepb.Challenge{})
	test.AssertError(t, err, "pbToVAChallenge did not fail")
	test.AssertEquals(t, err, ErrMissingParameters)
}

func TestValidationRecord(t *testing.T) {
	ip := net.ParseIP("1.1.1.1")
	vr := core.ValidationRecord{
		Hostname:          "host",
		Port:              "2020",
		AddressesResolved: []net.IP{ip},
		AddressUsed:       ip,
		URL:               "url",
		Authorities:       []string{"auth"},
	}

	pb, err := validationRecordToPB(vr)
	test.AssertNotError(t, err, "validationRecordToPB failed")
	test.Assert(t, pb != nil, "Return core.ValidationRecord is nil")

	recon, err := pbToValidationRecord(pb)
	test.AssertNotError(t, err, "pbToValidationRecord failed")
	test.AssertDeepEquals(t, recon, vr)
}

func TestValidationResult(t *testing.T) {
	ip := net.ParseIP("1.1.1.1")
	vrA := core.ValidationRecord{
		Hostname:          "hostA",
		Port:              "2020",
		AddressesResolved: []net.IP{ip},
		AddressUsed:       ip,
		URL:               "urlA",
		Authorities:       []string{"authA"},
	}
	vrB := core.ValidationRecord{
		Hostname:          "hostB",
		Port:              "2020",
		AddressesResolved: []net.IP{ip},
		AddressUsed:       ip,
		URL:               "urlB",
		Authorities:       []string{"authB"},
	}
	result := []core.ValidationRecord{vrA, vrB}
	prob := &probs.ProblemDetails{Type: probs.TLSProblem, Detail: "asd", HTTPStatus: 200}

	pb, err := validationResultToPB(result, prob)
	test.AssertNotError(t, err, "validationResultToPB failed")
	test.Assert(t, pb != nil, "Returned vapb.ValidationResult is nil")

	reconResult, reconProb, err := pbToValidationResult(pb)
	test.AssertNotError(t, err, "pbToValidationResult failed")
	test.AssertDeepEquals(t, reconResult, result)
	test.AssertDeepEquals(t, reconProb, prob)
}

func TestPerformValidationReq(t *testing.T) {
	var jwk jose.JsonWebKey
	err := json.Unmarshal([]byte(JWK1JSON), &jwk)
	test.AssertNotError(t, err, "Failed to unmarshal test key")
	domain := "example.com"
	chall := core.Challenge{
		ID:     10,
		Type:   core.ChallengeTypeDNS01,
		Status: core.StatusPending,
		Token:  "asd",
		ProvidedKeyAuthorization: "keyauth",
	}
	authz := core.Authorization{ID: "asd", RegistrationID: 10}

	pb, err := argsToPerformValidationRequest(domain, chall, authz)
	test.AssertNotError(t, err, "argsToPerformValidationRequest failed")
	test.Assert(t, pb != nil, "Return vapb.PerformValidationRequest is nil")

	reconDomain, reconChall, reconAuthz, err := performValidationReqToArgs(pb)
	test.AssertNotError(t, err, "performValidationReqToArgs failed")
	test.AssertEquals(t, reconDomain, domain)
	test.AssertDeepEquals(t, reconChall, chall)
	test.AssertDeepEquals(t, reconAuthz, authz)
}
