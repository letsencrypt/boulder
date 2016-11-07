package satest

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"golang.org/x/net/context"

	"github.com/letsencrypt/boulder/core"
	jose "gopkg.in/square/go-jose.v1"
)

var theKey = `{
    "kty": "RSA",
    "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
    "e": "AQAB"
}`

// GoodJWK returns a known-good JsonWebKey that is always the
// same. This a hack to allow both the CA and SA tests to benefit
// because the CA tests currently require a full-fledged
// SQLSAImpl. Long term, when the CA tests no longer need
// CreateWorkingRegistration, this and CreateWorkingRegistration can
// be pushed back into the SA tests proper.
func GoodJWK() jose.JsonWebKey {
	var jwk jose.JsonWebKey
	err := json.Unmarshal([]byte(theKey), &jwk)
	if err != nil {
		panic("known-good theKey is no longer known-good")
	}
	return jwk
}

// CreateWorkingRegistration inserts a new, correct Registration into
// SA using GoodKey under the hood. This a hack to allow both the CA
// and SA tests to benefit because the CA tests currently require a
// full-fledged SQLSAImpl. Long term, when the CA tests no longer need
// CreateWorkingRegistration, this and CreateWorkingRegistration can
// be pushed back into the SA tests proper.
func CreateWorkingRegistration(t *testing.T, sa core.StorageAdder) core.Registration {
	contact := "mailto:foo@example.com"
	contacts := &[]string{contact}
	reg, err := sa.NewRegistration(context.Background(), core.Registration{
		Key:       GoodJWK(),
		Contact:   contacts,
		InitialIP: net.ParseIP("88.77.66.11"),
		CreatedAt: time.Date(2003, 5, 10, 0, 0, 0, 0, time.UTC),
		Status:    core.StatusValid,
	})
	if err != nil {
		t.Fatalf("Unable to create new registration: %s", err)
	}
	return reg
}
