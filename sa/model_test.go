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

func TestV2AuthzModel(t *testing.T) {
	id := "1"
	ident := "example.com"
	reg := int64(1)
	status := string(core.StatusValid)
	expires := int64(1234)
	challType := string(core.ChallengeTypeHTTP01)
	token := "MTIz"
	hostname := "hostname"
	port := "port"
	challType2 := string(core.ChallengeTypeDNS01)
	statusPending := string(core.StatusPending)
	url := "url"
	authzPB := &corepb.Authorization{
		Id:             &id,
		Identifier:     &ident,
		RegistrationID: &reg,
		Status:         &status,
		Expires:        &expires,
		Challenges: []*corepb.Challenge{
			&corepb.Challenge{
				Type:   &challType,
				Status: &status,
				Token:  &token,
				Validationrecords: []*corepb.ValidationRecord{
					&corepb.ValidationRecord{
						Hostname:          &hostname,
						Port:              &port,
						AddressUsed:       []byte("1.2.3.4"),
						Url:               &url,
						AddressesResolved: [][]byte{[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}},
						AddressesTried:    [][]byte{[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}},
					},
				},
			},
			&corepb.Challenge{
				Type:   &challType2,
				Status: &statusPending,
				Token:  &token,
			},
		},
	}

	_, err := authzPBToModel(authzPB)
	test.AssertError(t, err, "authzPBToModel didn't fail when V2 wasn't set")

	v2 := true
	authzPB.V2 = &v2
	model, err := authzPBToModel(authzPB)
	test.AssertNotError(t, err, "authzPBToModel failed")

	authzPBOut, err := modelToAuthzPB(model)
	test.AssertNotError(t, err, "modelToAuthzPB failed")
	test.AssertDeepEquals(t, authzPB.Challenges, authzPBOut.Challenges)

	status = string(core.StatusInvalid)
	validationErr := probs.ConnectionFailure("weewoo")
	authzPB.Challenges[0].Status = &status
	authzPB.Challenges[0].Error, err = grpc.ProblemDetailsToPB(validationErr)
	test.AssertNotError(t, err, "grpc.ProblemDetailsToPB failed")
	model, err = authzPBToModel(authzPB)
	test.AssertNotError(t, err, "authzPBToModel failed")

	authzPBOut, err = modelToAuthzPB(model)
	test.AssertNotError(t, err, "modelToAuthzPB failed")
	test.AssertDeepEquals(t, authzPB.Challenges, authzPBOut.Challenges)

	authzPB.Challenges[1].Status = &status
	_, err = authzPBToModel(authzPB)
	test.AssertError(t, err, "authzPBToModel didn't fail with multiple non-pending challenges")
}
