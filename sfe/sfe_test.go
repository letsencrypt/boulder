package sfe

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"google.golang.org/grpc"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/must"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/unpause"

	rapb "github.com/letsencrypt/boulder/ra/proto"
)

type MockRegistrationAuthority struct {
	rapb.RegistrationAuthorityClient
}

func (ra *MockRegistrationAuthority) UnpauseAccount(context.Context, *rapb.UnpauseAccountRequest, ...grpc.CallOption) (*rapb.UnpauseAccountResponse, error) {
	return &rapb.UnpauseAccountResponse{}, nil
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
	test.AssertContains(t, responseWriter.Body.String(), "<title>Let's Encrypt - Self-Service Portal</title>")
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
	test.AssertContains(t, responseWriter.Body.String(), "Invalid unpause URL")

	// GET with an invalid JWT
	responseWriter = httptest.NewRecorder()
	sfe.UnpauseForm(responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(fmt.Sprintf(unpause.GetForm + "?jwt=x")),
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.AssertContains(t, responseWriter.Body.String(), "An error occurred while unpausing your account")

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
	test.AssertContains(t, responseWriter.Body.String(), "Action required to unpause your account")

	// POST with no JWT
	responseWriter = httptest.NewRecorder()
	sfe.UnpauseSubmit(responseWriter, &http.Request{
		Method: "POST",
		URL:    mustParseURL(unpausePostForm),
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.AssertContains(t, responseWriter.Body.String(), "Invalid unpause URL")

	// POST with an invalid JWT
	responseWriter = httptest.NewRecorder()
	sfe.UnpauseSubmit(responseWriter, &http.Request{
		Method: "POST",
		URL:    mustParseURL(fmt.Sprintf(unpausePostForm + "?jwt=x")),
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.AssertContains(t, responseWriter.Body.String(), "An error occurred while unpausing your account")

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
	test.AssertContains(t, responseWriter.Body.String(), "Account successfully unpaused")
}
