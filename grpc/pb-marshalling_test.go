package grpc

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"gopkg.in/square/go-jose.v2"

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
	var jwk jose.JSONWebKey
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

func TestChallenge(t *testing.T) {
	var jwk jose.JSONWebKey
	err := json.Unmarshal([]byte(JWK1JSON), &jwk)
	test.AssertNotError(t, err, "Failed to unmarshal test key")
	chall := core.Challenge{
		ID:     10,
		Type:   core.ChallengeTypeDNS01,
		Status: core.StatusPending,
		Token:  "asd",
		ProvidedKeyAuthorization: "keyauth",
	}

	pb, err := ChallengeToPB(chall)
	test.AssertNotError(t, err, "ChallengeToPB failed")
	test.Assert(t, pb != nil, "Returned corepb.Challenge is nil")

	recon, err := pbToChallenge(pb)
	test.AssertNotError(t, err, "pbToChallenge failed")
	test.AssertDeepEquals(t, recon, chall)

	ip := net.ParseIP("1.1.1.1")
	chall.ValidationRecord = []core.ValidationRecord{
		core.ValidationRecord{
			Hostname:          "host",
			Port:              "2020",
			AddressesResolved: []net.IP{ip},
			AddressUsed:       ip,
			URL:               "url",
			Authorities:       []string{"auth"},
			AddressesTried:    []net.IP{ip},
		},
	}
	chall.Error = &probs.ProblemDetails{Type: probs.TLSProblem, Detail: "asd", HTTPStatus: 200}
	pb, err = ChallengeToPB(chall)
	test.AssertNotError(t, err, "ChallengeToPB failed")
	test.Assert(t, pb != nil, "Returned corepb.Challenge is nil")

	recon, err = pbToChallenge(pb)
	test.AssertNotError(t, err, "pbToChallenge failed")
	test.AssertDeepEquals(t, recon, chall)

	_, err = pbToChallenge(nil)
	test.AssertError(t, err, "pbToChallenge did not fail")
	test.AssertEquals(t, err, ErrMissingParameters)
	_, err = pbToChallenge(&corepb.Challenge{})
	test.AssertError(t, err, "pbToChallenge did not fail")
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
		AddressesTried:    []net.IP{ip},
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
		AddressesTried:    []net.IP{ip},
	}
	vrB := core.ValidationRecord{
		Hostname:          "hostB",
		Port:              "2020",
		AddressesResolved: []net.IP{ip},
		AddressUsed:       ip,
		URL:               "urlB",
		Authorities:       []string{"authB"},
		AddressesTried:    []net.IP{ip},
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
	var jwk jose.JSONWebKey
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

func TestRegistration(t *testing.T) {
	contacts := []string{"email"}
	var key jose.JSONWebKey
	err := json.Unmarshal([]byte(`
		{
			"e": "AQAB",
			"kty": "RSA",
			"n": "tSwgy3ORGvc7YJI9B2qqkelZRUC6F1S5NwXFvM4w5-M0TsxbFsH5UH6adigV0jzsDJ5imAechcSoOhAh9POceCbPN1sTNwLpNbOLiQQ7RD5mY_pSUHWXNmS9R4NZ3t2fQAzPeW7jOfF0LKuJRGkekx6tXP1uSnNibgpJULNc4208dgBaCHo3mvaE2HV2GmVl1yxwWX5QZZkGQGjNDZYnjFfa2DKVvFs0QbAk21ROm594kAxlRlMMrvqlf24Eq4ERO0ptzpZgm_3j_e4hGRD39gJS7kAzK-j2cacFQ5Qi2Y6wZI2p-FCq_wiYsfEAIkATPBiLKl_6d_Jfcvs_impcXQ"
		}
	`), &key)
	test.AssertNotError(t, err, "Could not unmarshal testing key")
	inReg := core.Registration{
		ID:        1,
		Key:       &key,
		Contact:   &contacts,
		Agreement: "yup",
		InitialIP: net.ParseIP("1.1.1.1"),
		CreatedAt: time.Now().Round(0),
		Status:    core.StatusValid,
	}
	pbReg, err := registrationToPB(inReg)
	test.AssertNotError(t, err, "registrationToPB failed")
	outReg, err := pbToRegistration(pbReg)
	test.AssertNotError(t, err, "pbToRegistration failed")
	test.AssertDeepEquals(t, inReg, outReg)

	inReg.Contact = nil
	pbReg, err = registrationToPB(inReg)
	test.AssertNotError(t, err, "registrationToPB failed")
	pbReg.Contact = []string{}
	outReg, err = pbToRegistration(pbReg)
	test.AssertNotError(t, err, "pbToRegistration failed")
	test.AssertDeepEquals(t, inReg, outReg)

	var empty []string
	inReg.Contact = &empty
	pbReg, err = registrationToPB(inReg)
	test.AssertNotError(t, err, "registrationToPB failed")
	outReg, err = pbToRegistration(pbReg)
	test.AssertNotError(t, err, "pbToRegistration failed")
	test.Assert(t, *outReg.Contact != nil, "Empty slice was converted to a nil slice")
}

func TestAuthz(t *testing.T) {
	exp := time.Now().AddDate(0, 0, 1)
	identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "example.com"}
	combos := make([][]int, 1)
	combos[0] = []int{0, 1}
	challA := core.Challenge{
		ID:     10,
		Type:   core.ChallengeTypeDNS01,
		Status: core.StatusPending,
		Token:  "asd",
		ProvidedKeyAuthorization: "keyauth",
	}
	challB := core.Challenge{
		ID:     11,
		Type:   core.ChallengeTypeDNS01,
		Status: core.StatusPending,
		Token:  "asd2",
		ProvidedKeyAuthorization: "keyauth4",
	}
	inAuthz := core.Authorization{
		ID:             "1",
		Identifier:     identifier,
		RegistrationID: 5,
		Status:         core.StatusPending,
		Expires:        &exp,
		Challenges:     []core.Challenge{challA, challB},
		Combinations:   combos,
	}

	pbAuthz, err := AuthzToPB(inAuthz)
	test.AssertNotError(t, err, "AuthzToPB failed")
	outAuthz, err := PBToAuthz(pbAuthz)
	test.AssertNotError(t, err, "pbToAuthz failed")
	test.AssertDeepEquals(t, inAuthz, outAuthz)
}

func TestSCT(t *testing.T) {
	sct := core.SignedCertificateTimestamp{
		ID:                10,
		SCTVersion:        1,
		LogID:             "logid",
		Timestamp:         100,
		Extensions:        []byte{255},
		Signature:         []byte{1},
		CertificateSerial: "serial",
	}

	sctPB := sctToPB(sct)
	outSCT := pbToSCT(sctPB)

	test.AssertDeepEquals(t, sct, outSCT)
}

func TestCert(t *testing.T) {
	now := time.Now().Round(0)
	cert := core.Certificate{
		RegistrationID: 1,
		Serial:         "serial",
		Digest:         "digest",
		DER:            []byte{255},
		Issued:         now,
		Expires:        now.Add(time.Hour),
	}

	certPB := certToPB(cert)
	outCert := pbToCert(certPB)

	test.AssertDeepEquals(t, cert, outCert)
}

func TestOrderValid(t *testing.T) {
	testID := int64(1)
	testExpires := int64(1)
	emptyString := ""
	falseBool := false

	testCases := []struct {
		Name          string
		Order         *corepb.Order
		ExpectedValid bool
	}{
		{
			Name: "All valid",
			Order: &corepb.Order{
				Id:                &testID,
				RegistrationID:    &testID,
				Expires:           &testExpires,
				CertificateSerial: &emptyString,
				Authorizations:    []string{},
				Names:             []string{},
				BeganProcessing:   &falseBool,
			},
			ExpectedValid: true,
		},
		{
			Name: "Serial nil",
			Order: &corepb.Order{
				Id:              &testID,
				RegistrationID:  &testID,
				Expires:         &testExpires,
				Authorizations:  []string{},
				Names:           []string{},
				BeganProcessing: &falseBool,
			},
			ExpectedValid: true,
		},
		{
			Name:  "All nil",
			Order: &corepb.Order{},
		},
		{
			Name: "ID nil",
			Order: &corepb.Order{
				RegistrationID:    &testID,
				Expires:           &testExpires,
				CertificateSerial: &emptyString,
				Authorizations:    []string{},
				Names:             []string{},
				BeganProcessing:   &falseBool,
			},
		},
		{
			Name: "Reg ID nil",
			Order: &corepb.Order{
				Id:                &testID,
				Expires:           &testExpires,
				CertificateSerial: &emptyString,
				Authorizations:    []string{},
				Names:             []string{},
				BeganProcessing:   &falseBool,
			},
		},
		{
			Name: "Expires nil",
			Order: &corepb.Order{
				Id:                &testID,
				RegistrationID:    &testID,
				CertificateSerial: &emptyString,
				Authorizations:    []string{},
				Names:             []string{},
				BeganProcessing:   &falseBool,
			},
		},
		{
			Name: "Authorizations nil",
			Order: &corepb.Order{
				Id:                &testID,
				RegistrationID:    &testID,
				Expires:           &testExpires,
				CertificateSerial: &emptyString,
				Names:             []string{},
				BeganProcessing:   &falseBool,
			},
		},
		{
			Name: "BeganProcessing nil",
			Order: &corepb.Order{
				Id:                &testID,
				RegistrationID:    &testID,
				Expires:           &testExpires,
				CertificateSerial: &emptyString,
				Authorizations:    []string{},
				Names:             []string{},
			},
		},
		{
			Name: "Names nil",
			Order: &corepb.Order{
				Id:                &testID,
				RegistrationID:    &testID,
				Expires:           &testExpires,
				CertificateSerial: &emptyString,
				Authorizations:    []string{},
				BeganProcessing:   &falseBool,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result := orderValid(tc.Order)
			test.AssertEquals(t, result, tc.ExpectedValid)
		})
	}
}
