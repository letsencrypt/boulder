package sfe

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"golang.org/x/crypto/ocsp"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/must"
	"github.com/letsencrypt/boulder/revocation"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/unpause"

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

func setupSFE(t *testing.T) (SelfServiceFrontEndImpl, clock.FakeClock) {
	features.Reset()

	fc := clock.NewFake()
	// Set to some non-zero time.
	fc.Set(time.Date(2020, 10, 10, 0, 0, 0, 0, time.UTC))

	stats := metrics.NoopRegisterer

	mockSA := mocks.NewStorageAuthorityReadOnly(fc)

	hmacKey := cmd.HMACKeyConfig{KeyFile: "../test/secrets/sfe_unpause_key"}
	key, err := hmacKey.Load()
	test.AssertNotError(t, err, "Unable to load HMAC key")

	sfe, err := NewSelfServiceFrontEndImpl(
		stats,
		fc,
		blog.NewMock(),
		10*time.Second,
		&MockRegistrationAuthority{},
		mockSA,
		key,
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

	// GET with no JWT
	responseWriter := httptest.NewRecorder()
	sfe.UnpauseForm(responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(unpause.GetForm),
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.AssertContains(t, responseWriter.Body.String(), "request was invalid meaning that we could not")

	// GET with an invalid JWT
	responseWriter = httptest.NewRecorder()
	sfe.UnpauseForm(responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(fmt.Sprintf(unpause.GetForm + "?jwt=x")),
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.AssertContains(t, responseWriter.Body.String(), "error was encountered when attempting to unpause your account")

	// GET with a valid JWT
	unpauseSigner, err := unpause.NewJWTSigner(cmd.HMACKeyConfig{KeyFile: "../test/secrets/sfe_unpause_key"})
	test.AssertNotError(t, err, "Should have been able to create JWT signer, but could not")
	validJWT, err := unpause.GenerateJWT(unpauseSigner, 1234567890, []string{"example.com"}, time.Hour, fc)
	test.AssertNotError(t, err, "Should have been able to create JWT, but could not")
	responseWriter = httptest.NewRecorder()
	sfe.UnpauseForm(responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(fmt.Sprintf(unpause.GetForm + "?jwt=" + validJWT)),
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
		URL:    mustParseURL(fmt.Sprintf(unpausePostForm + "?jwt=" + validJWT)),
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
