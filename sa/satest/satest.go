package satest

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	jose "gopkg.in/square/go-jose.v2"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
)

var theKey = `{
    "kty": "RSA",
    "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
    "e": "AQAB"
}`

// GoodJWK returns a known-good JSONWebKey that is always the
// same. This a hack to allow both the CA and SA tests to benefit
// because the CA tests currently require a full-fledged
// SQLSAImpl. Long term, when the CA tests no longer need
// CreateWorkingRegistration, this and CreateWorkingRegistration can
// be pushed back into the SA tests proper.
func GoodJWK() *jose.JSONWebKey {
	var jwk jose.JSONWebKey
	err := json.Unmarshal([]byte(theKey), &jwk)
	if err != nil {
		panic("known-good theKey is no longer known-good")
	}
	return &jwk
}

// CreateWorkingRegistration inserts a new, correct Registration into
// SA using GoodKey under the hood. This a hack to allow both the CA
// and SA tests to benefit because the CA tests currently require a
// full-fledged SQLSAImpl. Long term, when the CA tests no longer need
// CreateWorkingRegistration, this and CreateWorkingRegistration can
// be pushed back into the SA tests proper.
func CreateWorkingRegistration(t *testing.T, sa core.StorageAdder) *corepb.Registration {
	initialIP, _ := net.ParseIP("88.77.66.11").MarshalText()
	reg, err := sa.NewRegistration(context.Background(), &corepb.Registration{
		Key:       []byte(theKey),
		Contact:   []string{"mailto:foo@example.com"},
		InitialIP: initialIP,
		CreatedAt: time.Date(2003, 5, 10, 0, 0, 0, 0, time.UTC).UnixNano(),
		Status:    string(core.StatusValid),
	})
	if err != nil {
		t.Fatalf("Unable to create new registration: %s", err)
	}
	return reg
}
