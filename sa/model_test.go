package sa

import (
	"testing"

	"github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/probs"

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
	badJSONErr, ok := err.(errBadJSON)
	test.AssertEquals(t, ok, true)
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
				Type:   string(core.ChallengeTypeHTTP01),
				Status: string(core.StatusValid),
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
			badJSONErr, ok := err.(errBadJSON)
			test.AssertEquals(t, ok, true)
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
	badJSONErr, ok := err.(errBadJSON)
	test.AssertEquals(t, ok, true)
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
			badJSONErr, ok := err.(errBadJSON)
			test.AssertEquals(t, ok, true)
			test.AssertEquals(t, string(badJSONErr.json), string(badJSON))
		})
	}
}
