package sa

import (
	"testing"

	"github.com/letsencrypt/boulder/features"
)

func TestModelToRegistrationNilContact(t *testing.T) {
	defer features.Reset()
	reg, err := modelToRegistration(&regModelv2{
		regModelv1: regModelv1{
			Key:     []byte(`{"kty":"RSA","n":"AQAB","e":"AQAB"}`),
			Contact: nil,
		}})
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
	defer features.Reset()
	reg, err := modelToRegistration(&regModelv2{
		regModelv1: regModelv1{
			Key:     []byte(`{"kty":"RSA","n":"AQAB","e":"AQAB"}`),
			Contact: []string{},
		}})
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
