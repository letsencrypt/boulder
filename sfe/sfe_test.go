package sfe

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jmhodges/clock"
	"golang.org/x/crypto/ocsp"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/must"
	"github.com/letsencrypt/boulder/revocation"
	"github.com/letsencrypt/boulder/test"

	capb "github.com/letsencrypt/boulder/ca/proto"
	corepb "github.com/letsencrypt/boulder/core/proto"
	rapb "github.com/letsencrypt/boulder/ra/proto"
)

type MockRegistrationAuthority struct {
	lastRevocationReason revocation.Reason
}

func (ra *MockRegistrationAuthority) NewRegistration(ctx context.Context, in *corepb.Registration, _ ...grpc.CallOption) (*corepb.Registration, error) {
	in.Id = 1
	created := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	in.CreatedAt = timestamppb.New(created)
	return in, nil
}

func (ra *MockRegistrationAuthority) UpdateRegistration(ctx context.Context, in *rapb.UpdateRegistrationRequest, _ ...grpc.CallOption) (*corepb.Registration, error) {
	if !bytes.Equal(in.Base.Key, in.Update.Key) {
		in.Base.Key = in.Update.Key
	}
	return in.Base, nil
}

func (ra *MockRegistrationAuthority) PerformValidation(context.Context, *rapb.PerformValidationRequest, ...grpc.CallOption) (*corepb.Authorization, error) {
	return &corepb.Authorization{}, nil
}

func (ra *MockRegistrationAuthority) RevokeCertByApplicant(ctx context.Context, in *rapb.RevokeCertByApplicantRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	ra.lastRevocationReason = revocation.Reason(in.Code)
	return &emptypb.Empty{}, nil
}

func (ra *MockRegistrationAuthority) RevokeCertByKey(ctx context.Context, in *rapb.RevokeCertByKeyRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	ra.lastRevocationReason = revocation.Reason(ocsp.KeyCompromise)
	return &emptypb.Empty{}, nil
}

func (ra *MockRegistrationAuthority) GenerateOCSP(ctx context.Context, req *rapb.GenerateOCSPRequest, _ ...grpc.CallOption) (*capb.OCSPResponse, error) {
	return nil, nil
}

func (ra *MockRegistrationAuthority) AdministrativelyRevokeCertificate(context.Context, *rapb.AdministrativelyRevokeCertificateRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (ra *MockRegistrationAuthority) OnValidationUpdate(context.Context, core.Authorization, ...grpc.CallOption) error {
	return nil
}

func (ra *MockRegistrationAuthority) DeactivateAuthorization(context.Context, *corepb.Authorization, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (ra *MockRegistrationAuthority) DeactivateRegistration(context.Context, *corepb.Registration, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (ra *MockRegistrationAuthority) UnpauseAccount(context.Context, *rapb.UnpauseAccountRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (ra *MockRegistrationAuthority) NewOrder(ctx context.Context, in *rapb.NewOrderRequest, _ ...grpc.CallOption) (*corepb.Order, error) {
	created := time.Date(2021, 1, 1, 1, 1, 1, 0, time.UTC)
	expires := time.Date(2021, 2, 1, 1, 1, 1, 0, time.UTC)

	return &corepb.Order{
		Id:               1,
		RegistrationID:   in.RegistrationID,
		Created:          timestamppb.New(created),
		Expires:          timestamppb.New(expires),
		Names:            in.Names,
		Status:           string(core.StatusPending),
		V2Authorizations: []int64{1},
	}, nil
}

func (ra *MockRegistrationAuthority) FinalizeOrder(ctx context.Context, in *rapb.FinalizeOrderRequest, _ ...grpc.CallOption) (*corepb.Order, error) {
	in.Order.Status = string(core.StatusProcessing)
	return in.Order, nil
}

func mustParseURL(s string) *url.URL {
	return must.Do(url.Parse(s))
}

const hmacKey = "pcl04dl3tt3rb1gb4dd4db0d34ts000p"

func setupSFE(t *testing.T) (SelfServiceFrontEndImpl, clock.FakeClock) {
	features.Reset()

	fc := clock.NewFake()
	// Set to some non-zero time.
	fc.Set(time.Date(2020, 10, 10, 0, 0, 0, 0, time.UTC))

	stats := metrics.NoopRegisterer

	mockSA := mocks.NewStorageAuthorityReadOnly(fc)

	sfe, err := NewSelfServiceFrontEndImpl(
		stats,
		fc,
		blog.NewMock(),
		10*time.Second,
		&MockRegistrationAuthority{},
		mockSA,
		[]byte(hmacKey),
	)
	test.AssertNotError(t, err, "Unable to create SFE")

	return sfe, fc
}

func TestIndexPath(t *testing.T) {
	t.Parallel()
	sfe, _ := setupSFE(t)
	responseWriter := httptest.NewRecorder()
	sfe.Index(responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL("/"),
	})

	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.AssertContains(t, responseWriter.Body.String(), "<title>Self-Service Frontend</title>")
}

func TestBuildIDPath(t *testing.T) {
	t.Parallel()
	sfe, _ := setupSFE(t)
	responseWriter := httptest.NewRecorder()
	sfe.BuildID(responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL("/build"),
	})

	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.AssertContains(t, responseWriter.Body.String(), "Boulder=(")
}

func TestUnpausePaths(t *testing.T) {
	t.Parallel()
	sfe, fc := setupSFE(t)
	now := fc.Now()

	// GET with no JWT
	responseWriter := httptest.NewRecorder()
	sfe.UnpauseForm(responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(unpauseGetForm),
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.AssertContains(t, responseWriter.Body.String(), "request was invalid meaning that we could not")

	// GET with an invalid JWT
	responseWriter = httptest.NewRecorder()
	sfe.UnpauseForm(responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(fmt.Sprintf(unpauseGetForm + "?jwt=x")),
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.AssertContains(t, responseWriter.Body.String(), "error was encountered when attempting to unpause your account")

	// GET with a valid JWT
	validJWT, err := makeJWTForAccount(now, now, now.Add(24*time.Hour), []byte(hmacKey), 1, "v1", "example.com")
	test.AssertNotError(t, err, "Should have been able to create JWT, but could not")
	responseWriter = httptest.NewRecorder()
	sfe.UnpauseForm(responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(fmt.Sprintf(unpauseGetForm + "?jwt=" + string(validJWT))),
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.AssertContains(t, responseWriter.Body.String(), "This action will allow you to resume")

	// POST with no JWT
	responseWriter = httptest.NewRecorder()
	sfe.UnpauseSubmit(responseWriter, &http.Request{
		Method: "POST",
		URL:    mustParseURL(unpausePostForm),
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.AssertContains(t, responseWriter.Body.String(), "request was invalid meaning that we could not")

	// POST with an invalid JWT
	responseWriter = httptest.NewRecorder()
	sfe.UnpauseSubmit(responseWriter, &http.Request{
		Method: "POST",
		URL:    mustParseURL(fmt.Sprintf(unpausePostForm + "?jwt=x")),
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.AssertContains(t, responseWriter.Body.String(), "An error was encountered when attempting to unpause")

	// POST with a valid JWT redirects to a success page
	responseWriter = httptest.NewRecorder()
	sfe.UnpauseSubmit(responseWriter, &http.Request{
		Method: "POST",
		URL:    mustParseURL(fmt.Sprintf(unpausePostForm + "?jwt=" + string(validJWT))),
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusFound)
	test.AssertEquals(t, unpauseStatus, responseWriter.Result().Header.Get("Location"))

	// Redirecting after a successful unpause POST displays the success page.
	responseWriter = httptest.NewRecorder()
	sfe.UnpauseStatus(responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(unpauseStatus),
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.AssertContains(t, responseWriter.Body.String(), "Your ACME account has been unpaused.")
}

// makeJWTForAccount is a standin for a WFE method that returns an unpauseJWT or
// an error. The JWT contains a set of claims which should be validated by the
// caller.
func makeJWTForAccount(notBefore time.Time, issuedAt time.Time, expiresAt time.Time, hmacKey []byte, regID int64, apiVersion string, pausedDomains string) (unpauseJWT, error) {
	if len(hmacKey) != 32 {
		return "", fmt.Errorf("invalid seed length")
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: hmacKey}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", fmt.Errorf("making signer: %s", err)
	}

	// Ensure that we test an empty subject
	var subject string
	if regID == 0 {
		subject = ""
	} else {
		subject = fmt.Sprint(regID)
	}

	// Ensure that we test receiving an empty API version string while
	// defaulting the rest to match SFE unpausePath.
	if apiVersion == "magicEmptyString" {
		apiVersion = ""
	} else if apiVersion == "" {
		apiVersion = "v1"
	}

	// Ensure that we always send at least one domain in the JWT.
	if pausedDomains == "" {
		pausedDomains = "example.com"
	}

	// The SA returns a maximum of 15 domains and the SFE displays some text
	// about "potentially more domains" being paused.
	domains := strings.Split(pausedDomains, ",")
	if len(domains) > 15 {
		domains = domains[:15]
	}

	// Join slice back into a comma separated string with the maximum of 15
	// domains.
	pausedDomains = strings.Join(domains, ",")

	customClaims := struct {
		Version string `json:"apiVersion,omitempty"`
		Domains string `json:"pausedDomains,omitempty"`
	}{
		apiVersion,
		pausedDomains,
	}

	wfeClaims := jwt.Claims{
		Issuer:    "WFE",
		Subject:   subject,
		Audience:  jwt.Audience{"SFE Unpause"},
		NotBefore: jwt.NewNumericDate(notBefore),
		IssuedAt:  jwt.NewNumericDate(issuedAt),
		Expiry:    jwt.NewNumericDate(expiresAt),
	}

	signedJWT, err := jwt.Signed(signer).Claims(&wfeClaims).Claims(&customClaims).Serialize()
	if err != nil {
		return "", fmt.Errorf("signing JWT: %s", err)
	}

	return unpauseJWT(signedJWT), nil
}

func TestValidateJWT(t *testing.T) {
	t.Parallel()
	sfe, fc := setupSFE(t)

	now := fc.Now()
	originalClock := fc
	testCases := []struct {
		Name                        string
		IssuedAt                    time.Time
		NotBefore                   time.Time
		ExpiresAt                   time.Time
		HMACKey                     string
		RegID                       int64  // Default value set in makeJWTForAccount
		Version                     string // Default value set in makeJWTForAccount
		PausedDomains               string // Default value set in makeJWTForAccount
		ExpectedPausedDomains       []string
		ExpectedMakeJWTSubstr       string
		ExpectedValidationErrSubstr string
	}{
		{
			Name:                  "valid",
			IssuedAt:              now,
			NotBefore:             now,
			ExpiresAt:             now.Add(1 * time.Hour),
			HMACKey:               hmacKey,
			RegID:                 1,
			ExpectedPausedDomains: []string{"example.com"},
		},
		{
			Name:                  "valid, but more than 15 domains sent",
			IssuedAt:              now,
			NotBefore:             now,
			ExpiresAt:             now.Add(1 * time.Hour),
			HMACKey:               hmacKey,
			RegID:                 1,
			PausedDomains:         "1.example.com,2.example.com,3.example.com,4.example.com,5.example.com,6.example.com,7.example.com,8.example.com,9.example.com,10.example.com,11.example.com,12.example.com,13.example.com,14.example.com,15.example.com,16.example.com",
			ExpectedPausedDomains: []string{"1.example.com", "2.example.com", "3.example.com", "4.example.com", "5.example.com", "6.example.com", "7.example.com", "8.example.com", "9.example.com", "10.example.com", "11.example.com", "12.example.com", "13.example.com", "14.example.com", "15.example.com"},
		},
		{
			Name:                        "apiVersion mismatch",
			IssuedAt:                    now,
			NotBefore:                   now.Add(5 * time.Minute),
			ExpiresAt:                   now.Add(1 * time.Hour),
			HMACKey:                     hmacKey,
			RegID:                       1,
			Version:                     "v2",
			ExpectedValidationErrSubstr: "incompatible API version",
		},
		{
			Name:                        "no API specified in claim",
			IssuedAt:                    now,
			NotBefore:                   now.Add(5 * time.Minute),
			ExpiresAt:                   now.Add(1 * time.Hour),
			HMACKey:                     hmacKey,
			RegID:                       1,
			Version:                     "magicEmptyString",
			ExpectedValidationErrSubstr: "no API version",
		},
		{
			Name:                        "creating JWT with empty seed fails",
			IssuedAt:                    now,
			NotBefore:                   now.Add(5 * time.Minute),
			ExpiresAt:                   now.Add(1 * time.Hour),
			HMACKey:                     "",
			RegID:                       1,
			ExpectedMakeJWTSubstr:       "invalid seed length",
			ExpectedValidationErrSubstr: "JWS format must have",
		},
		{
			Name:                        "registration ID is required to pass validation",
			IssuedAt:                    now,
			NotBefore:                   now.Add(5 * time.Minute),
			ExpiresAt:                   now.Add(24 * time.Hour),
			HMACKey:                     hmacKey,
			RegID:                       0, // This is a magic case where 0 is turned into an empty string in the Subject field of a jwt.Claims
			ExpectedValidationErrSubstr: "required for account unpausing",
		},
		{
			Name:                        "validating expired JWT fails",
			IssuedAt:                    now,
			NotBefore:                   now.Add(5 * time.Minute),
			ExpiresAt:                   now.Add(-24 * time.Hour),
			HMACKey:                     hmacKey,
			RegID:                       1,
			ExpectedValidationErrSubstr: "token is expired (exp)",
		},
		{
			Name:                        "validating JWT with hash derived from different seed fails",
			IssuedAt:                    now,
			NotBefore:                   now.Add(5 * time.Minute),
			ExpiresAt:                   now.Add(1 * time.Hour),
			HMACKey:                     "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			RegID:                       1,
			ExpectedValidationErrSubstr: "cryptographic primitive",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			fc = originalClock
			newJWT, err := makeJWTForAccount(tc.NotBefore, tc.IssuedAt, tc.ExpiresAt, []byte(tc.HMACKey), tc.RegID, tc.Version, tc.PausedDomains)
			if tc.ExpectedMakeJWTSubstr != "" || string(newJWT) == "" {
				test.AssertError(t, err, "JWT was created but should not have been")
				test.AssertContains(t, err.Error(), tc.ExpectedMakeJWTSubstr)
			} else {
				test.AssertNotError(t, err, "Should have been able to create a JWT")
			}

			// Advance the clock an arbitrary amount. The WFE sets a notBefore
			// claim in the JWT as a first pass annoyance for clients attempting
			// to automate unpausing.
			fc.Add(10 * time.Minute)
			_, domains, err := sfe.validateUnpauseJWTforAccount(newJWT)
			if tc.ExpectedValidationErrSubstr != "" || err != nil {
				test.AssertError(t, err, "Error expected, but received none")
				test.AssertContains(t, err.Error(), tc.ExpectedValidationErrSubstr)
			} else {
				test.AssertNotError(t, err, "Unable to validate JWT")
				test.AssertDeepEquals(t, domains, tc.ExpectedPausedDomains)
			}
		})
	}
}
