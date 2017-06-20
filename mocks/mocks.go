package mocks

import (
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"github.com/jmhodges/clock"
	"golang.org/x/net/context"
	"gopkg.in/square/go-jose.v1"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/revocation"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

// StorageAuthority is a mock
type StorageAuthority struct {
	clk               clock.Clock
	authorizedDomains map[string]bool
}

// NewStorageAuthority creates a new mock storage authority
// with the given clock.
func NewStorageAuthority(clk clock.Clock) *StorageAuthority {
	return &StorageAuthority{clk: clk}
}

const (
	test1KeyPublicJSON = `
{
	"kty":"RSA",
	"n":"yNWVhtYEKJR21y9xsHV-PD_bYwbXSeNuFal46xYxVfRL5mqha7vttvjB_vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K_klBYN8oYvTwwmeSkAz6ut7ZxPv-nZaT5TJhGk0NT2kh_zSpdriEJ_3vW-mqxYbbBmpvHqsa1_zx9fSuHYctAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV-mzfMyboQjujPh7aNJxAWSq4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF-w8hOTI3XXohUdu29Se26k2B0PolDSuj0GIQU6-W9TdLXSjBb2SpQ",
	"e":"AAEAAQ"
}`
	test2KeyPublicJSON = `{
		"kty":"RSA",
		"n":"qnARLrT7Xz4gRcKyLdydmCr-ey9OuPImX4X40thk3on26FkMznR3fRjs66eLK7mmPcBZ6uOJseURU6wAaZNmemoYx1dMvqvWWIyiQleHSD7Q8vBrhR6uIoO4jAzJZR-ChzZuSDt7iHN-3xUVspu5XGwXU_MVJZshTwp4TaFx5elHIT_ObnTvTOU3Xhish07AbgZKmWsVbXh5s-CrIicU4OexJPgunWZ_YJJueOKmTvnLlTV4MzKR2oZlBKZ27S0-SfdV_QDx_ydle5oMAyKVtlAV35cyPMIsYNwgUGBCdY_2Uzi5eX0lTc7MPRwz6qR1kip-i59VcGcUQgqHV6Fyqw",
		"e":"AAEAAQ"
	}`

	testE1KeyPublicJSON = `{
     "kty":"EC",
     "crv":"P-256",
     "x":"FwvSZpu06i3frSk_mz9HcD9nETn4wf3mQ-zDtG21Gao",
     "y":"S8rR-0dWa8nAcw1fbunF_ajS3PQZ-QwLps-2adgLgPk"
   }`
	testE2KeyPublicJSON = `{
     "kty":"EC",
     "crv":"P-256",
     "x":"S8FOmrZ3ywj4yyFqt0etAD90U-EnkNaOBSLfQmf7pNg",
     "y":"vMvpDyqFDRHjGfZ1siDOm5LS6xNdR5xTpyoQGLDOX2Q"
   }`
	test3KeyPublicJSON = `{"kty":"RSA","n":"uTQER6vUA1RDixS8xsfCRiKUNGRzzyIK0MhbS2biClShbb0hSx2mPP7gBvis2lizZ9r-y9hL57kNQoYCKndOBg0FYsHzrQ3O9AcoV1z2Mq-XhHZbFrVYaXI0M3oY9BJCWog0dyi3XC0x8AxC1npd1U61cToHx-3uSvgZOuQA5ffEn5L38Dz1Ti7OV3E4XahnRJvejadUmTkki7phLBUXm5MnnyFm0CPpf6ApV7zhLjN5W-nV0WL17o7v8aDgV_t9nIdi1Y26c3PlCEtiVHZcebDH5F1Deta3oLLg9-g6rWnTqPbY3knffhp4m0scLD6e33k8MtzxDX_D7vHsg0_X1w","e":"AQAB"}`
	test4KeyPublicJSON = `{
    "kty":"RSA",
    "n":"qih-cx32M0wq8MhhN-kBi2xPE-wnw4_iIg1hWO5wtBfpt2PtWikgPuBT6jvK9oyQwAWbSfwqlVZatMPY_-3IyytMNb9R9OatNr6o5HROBoyZnDVSiC4iMRd7bRl_PWSIqj_MjhPNa9cYwBdW5iC3jM5TaOgmp0-YFm4tkLGirDcIBDkQYlnv9NKILvuwqkapZ7XBixeqdCcikUcTRXW5unqygO6bnapzw-YtPsPPlj4Ih3SvK4doyziPV96U8u5lbNYYEzYiW1mbu9n0KLvmKDikGcdOpf6-yRa_10kMZyYQatY1eclIKI0xb54kbluEl0GQDaL5FxLmiKeVnsapzw",
    "e":"AQAB"
  }`

	agreementURL = "http://example.invalid/terms"
)

// GetRegistration is a mock
func (sa *StorageAuthority) GetRegistration(_ context.Context, id int64) (core.Registration, error) {
	if id == 100 {
		// Tag meaning "Missing"
		return core.Registration{}, errors.New("missing")
	}
	if id == 101 {
		// Tag meaning "Malformed"
		return core.Registration{}, nil
	}

	keyJSON := []byte(test1KeyPublicJSON)
	var parsedKey jose.JsonWebKey
	err := parsedKey.UnmarshalJSON(keyJSON)
	if err != nil {
		return core.Registration{}, err
	}

	return core.Registration{
		ID:        id,
		Key:       &parsedKey,
		Agreement: agreementURL,
		InitialIP: net.ParseIP("5.6.7.8"),
		CreatedAt: time.Date(2003, 9, 27, 0, 0, 0, 0, time.UTC),
		Status:    core.StatusValid,
	}, nil
}

// GetRegistrationByKey is a mock
func (sa *StorageAuthority) GetRegistrationByKey(_ context.Context, jwk *jose.JsonWebKey) (core.Registration, error) {
	var test1KeyPublic jose.JsonWebKey
	var test2KeyPublic jose.JsonWebKey
	var test3KeyPublic jose.JsonWebKey
	var test4KeyPublic jose.JsonWebKey
	var testE1KeyPublic jose.JsonWebKey
	var testE2KeyPublic jose.JsonWebKey
	var err error
	err = test1KeyPublic.UnmarshalJSON([]byte(test1KeyPublicJSON))
	if err != nil {
		return core.Registration{}, err
	}
	err = test2KeyPublic.UnmarshalJSON([]byte(test2KeyPublicJSON))
	if err != nil {
		return core.Registration{}, err
	}
	err = test3KeyPublic.UnmarshalJSON([]byte(test3KeyPublicJSON))
	if err != nil {
		return core.Registration{}, err
	}
	err = test4KeyPublic.UnmarshalJSON([]byte(test4KeyPublicJSON))
	if err != nil {
		return core.Registration{}, err
	}
	err = testE1KeyPublic.UnmarshalJSON([]byte(testE1KeyPublicJSON))
	if err != nil {
		panic(err)
	}
	err = testE2KeyPublic.UnmarshalJSON([]byte(testE2KeyPublicJSON))
	if err != nil {
		panic(err)
	}

	contacts := []string{"mailto:person@mail.com"}

	if core.KeyDigestEquals(jwk, test1KeyPublic) {
		return core.Registration{
			ID:        1,
			Key:       jwk,
			Agreement: agreementURL,
			Contact:   &contacts,
			Status:    core.StatusValid,
		}, nil
	}

	if core.KeyDigestEquals(jwk, test2KeyPublic) {
		// No key found
		return core.Registration{ID: 2}, berrors.NotFoundError("reg not found")
	}

	if core.KeyDigestEquals(jwk, test4KeyPublic) {
		// No key found
		return core.Registration{ID: 5}, berrors.NotFoundError("reg not found")
	}

	if core.KeyDigestEquals(jwk, testE1KeyPublic) {
		return core.Registration{ID: 3, Key: jwk, Agreement: agreementURL}, nil
	}

	if core.KeyDigestEquals(jwk, testE2KeyPublic) {
		return core.Registration{ID: 4}, berrors.NotFoundError("reg not found")
	}

	if core.KeyDigestEquals(jwk, test3KeyPublic) {
		// deactivated registration
		return core.Registration{
			ID:        2,
			Key:       jwk,
			Agreement: agreementURL,
			Contact:   &contacts,
			Status:    core.StatusDeactivated,
		}, nil
	}

	// Return a fake registration. Make sure to fill the key field to avoid marshaling errors.
	return core.Registration{ID: 1, Key: &test1KeyPublic, Agreement: agreementURL}, nil
}

// GetAuthorization is a mock
func (sa *StorageAuthority) GetAuthorization(_ context.Context, id string) (core.Authorization, error) {
	authz := core.Authorization{
		ID:             "valid",
		Status:         core.StatusValid,
		RegistrationID: 1,
		Identifier:     core.AcmeIdentifier{Type: "dns", Value: "not-an-example.com"},
		Challenges: []core.Challenge{
			{
				ID:   23,
				Type: "dns",
			},
		},
	}

	if id == "valid" {
		exp := sa.clk.Now().AddDate(100, 0, 0)
		authz.Expires = &exp
		authz.Challenges[0].URI = "http://localhost:4300/acme/challenge/valid/23"
		return authz, nil
	} else if id == "expired" {
		exp := sa.clk.Now().AddDate(0, -1, 0)
		authz.Expires = &exp
		authz.Challenges[0].URI = "http://localhost:4300/acme/challenge/expired/23"
		return authz, nil
	} else if id == "error_result" {
		return core.Authorization{}, fmt.Errorf("Unspecified database error")
	}

	return core.Authorization{}, sql.ErrNoRows
}

// RevokeAuthorizationsByDomain is a mock
func (sa *StorageAuthority) RevokeAuthorizationsByDomain(_ context.Context, ident core.AcmeIdentifier) (int64, int64, error) {
	return 0, 0, nil
}

// GetCertificate is a mock
func (sa *StorageAuthority) GetCertificate(_ context.Context, serial string) (core.Certificate, error) {
	// Serial ee == 238.crt
	if serial == "0000000000000000000000000000000000ee" {
		certPemBytes, _ := ioutil.ReadFile("test/238.crt")
		certBlock, _ := pem.Decode(certPemBytes)
		return core.Certificate{
			RegistrationID: 1,
			DER:            certBlock.Bytes,
		}, nil
	} else if serial == "0000000000000000000000000000000000b2" {
		certPemBytes, _ := ioutil.ReadFile("test/178.crt")
		certBlock, _ := pem.Decode(certPemBytes)
		return core.Certificate{
			RegistrationID: 1,
			DER:            certBlock.Bytes,
		}, nil
	} else {
		return core.Certificate{}, errors.New("No cert")
	}
}

// GetCertificateStatus is a mock
func (sa *StorageAuthority) GetCertificateStatus(_ context.Context, serial string) (core.CertificateStatus, error) {
	// Serial ee == 238.crt
	if serial == "0000000000000000000000000000000000ee" {
		return core.CertificateStatus{
			Status: core.OCSPStatusGood,
		}, nil
	} else if serial == "0000000000000000000000000000000000b2" {
		return core.CertificateStatus{
			Status: core.OCSPStatusRevoked,
		}, nil
	} else {
		return core.CertificateStatus{}, errors.New("No cert status")
	}
}

// AddCertificate is a mock
func (sa *StorageAuthority) AddCertificate(_ context.Context, certDER []byte, regID int64, _ []byte) (digest string, err error) {
	return
}

// FinalizeAuthorization is a mock
func (sa *StorageAuthority) FinalizeAuthorization(_ context.Context, authz core.Authorization) (err error) {
	return
}

// MarkCertificateRevoked is a mock
func (sa *StorageAuthority) MarkCertificateRevoked(_ context.Context, serial string, reasonCode revocation.Reason) (err error) {
	return
}

// NewPendingAuthorization is a mock
func (sa *StorageAuthority) NewPendingAuthorization(_ context.Context, authz core.Authorization) (output core.Authorization, err error) {
	return
}

// NewRegistration is a mock
func (sa *StorageAuthority) NewRegistration(_ context.Context, reg core.Registration) (regR core.Registration, err error) {
	return
}

// UpdatePendingAuthorization is a mock
func (sa *StorageAuthority) UpdatePendingAuthorization(_ context.Context, authz core.Authorization) (err error) {
	return
}

// UpdateRegistration is a mock
func (sa *StorageAuthority) UpdateRegistration(_ context.Context, reg core.Registration) (err error) {
	return
}

// GetSCTReceipt  is a mock
func (sa *StorageAuthority) GetSCTReceipt(_ context.Context, serial string, logID string) (sct core.SignedCertificateTimestamp, err error) {
	return
}

// AddSCTReceipt is a mock
func (sa *StorageAuthority) AddSCTReceipt(_ context.Context, sct core.SignedCertificateTimestamp) (err error) {
	if sct.Signature == nil {
		err = fmt.Errorf("Bad times")
	}
	return
}

// CountFQDNSets is a mock
func (sa *StorageAuthority) CountFQDNSets(_ context.Context, since time.Duration, names []string) (int64, error) {
	return 0, nil
}

// FQDNSetExists is a mock
func (sa *StorageAuthority) FQDNSetExists(_ context.Context, names []string) (bool, error) {
	return false, nil
}

// GetValidAuthorizations is a mock
func (sa *StorageAuthority) GetValidAuthorizations(_ context.Context, regID int64, names []string, now time.Time) (map[string]*core.Authorization, error) {
	if regID == 1 {
		auths := make(map[string]*core.Authorization)
		for _, name := range names {
			if sa.authorizedDomains[name] || name == "not-an-example.com" {
				exp := now.AddDate(100, 0, 0)
				auths[name] = &core.Authorization{
					Status:         core.StatusValid,
					RegistrationID: 1,
					Expires:        &exp,
					Identifier: core.AcmeIdentifier{
						Type:  "dns",
						Value: name,
					},
				}
			}
		}
		return auths, nil
	} else if regID == 2 {
		return map[string]*core.Authorization{}, nil
	} else if regID == 5 {
		return map[string]*core.Authorization{"bad.example.com": nil}, nil
	}
	return nil, nil
}

// CountCertificatesRange is a mock
func (sa *StorageAuthority) CountCertificatesRange(_ context.Context, _, _ time.Time) (int64, error) {
	return 0, nil
}

// CountCertificatesByNames is a mock
func (sa *StorageAuthority) CountCertificatesByNames(_ context.Context, _ []string, _, _ time.Time) (ret []*sapb.CountByNames_MapElement, err error) {
	return
}

// CountCertificatesByExactNames is a mock
func (sa *StorageAuthority) CountCertificatesByExactNames(_ context.Context, _ []string, _, _ time.Time) (ret []*sapb.CountByNames_MapElement, err error) {
	return
}

// CountRegistrationsByIP is a mock
func (sa *StorageAuthority) CountRegistrationsByIP(_ context.Context, _ net.IP, _, _ time.Time) (int, error) {
	return 0, nil
}

// CountRegistrationsByIPRange is a mock
func (sa *StorageAuthority) CountRegistrationsByIPRange(_ context.Context, _ net.IP, _, _ time.Time) (int, error) {
	return 0, nil
}

// CountPendingAuthorizations is a mock
func (sa *StorageAuthority) CountPendingAuthorizations(_ context.Context, _ int64) (int, error) {
	return 0, nil
}

// DeactivateAuthorization is a mock
func (sa *StorageAuthority) DeactivateAuthorization(_ context.Context, _ string) error {
	return nil
}

// DeactivateRegistration is a mock
func (sa *StorageAuthority) DeactivateRegistration(_ context.Context, _ int64) error {
	return nil
}

// Publisher is a mock
type Publisher struct {
	// empty
}

// SubmitToCT is a mock
func (*Publisher) SubmitToCT(_ context.Context, der []byte) error {
	return nil
}

// SubmitToSingleCT is a mock
func (*Publisher) SubmitToSingleCT(_ context.Context, _, _ string, _ []byte) error {
	return nil
}

// Mailer is a mock
type Mailer struct {
	Messages []MailerMessage
}

// MailerMessage holds the captured emails from SendMail()
type MailerMessage struct {
	To      string
	Subject string
	Body    string
}

// Clear removes any previously recorded messages
func (m *Mailer) Clear() {
	m.Messages = nil
}

// SendMail is a mock
func (m *Mailer) SendMail(to []string, subject, msg string) error {
	for _, rcpt := range to {
		m.Messages = append(m.Messages, MailerMessage{
			To:      rcpt,
			Subject: subject,
			Body:    msg,
		})
	}
	return nil
}

// Close is a mock
func (m *Mailer) Close() error {
	return nil
}

// Connect is a mock
func (m *Mailer) Connect() error {
	return nil
}
