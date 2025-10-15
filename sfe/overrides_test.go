package sfe

import (
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/mocks"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	rl "github.com/letsencrypt/boulder/ratelimits"
	"github.com/letsencrypt/boulder/sfe/zendesk"
	"github.com/letsencrypt/boulder/test/zendeskfake"
	"google.golang.org/grpc"
)

const (
	apiTokenEmail = "tester@example.com"
	apiToken      = "someToken"
)

func createFakeZendeskClientServer(t *testing.T) (*zendeskfake.Server, *zendesk.Client) {
	t.Helper()

	server := zendeskfake.NewServer(apiTokenEmail, apiToken, nil)
	ts := httptest.NewServer(server.Handler())
	t.Cleanup(ts.Close)

	client, err := zendesk.NewClient(ts.URL, apiTokenEmail, apiToken, map[string]int64{
		"organization":     1234567,
		"tier":             2345678,
		"rateLimit":        3456789,
		"reviewStatus":     34567890,
		"accountURI":       45678901,
		"registeredDomain": 56789012,
		"ipAddress":        67890123,
	})
	if err != nil {
		t.Errorf("NewClient(%q) returned error: %s", ts.URL, err)
	}
	return server, client
}

func minimalTemplates(t *testing.T) *template.Template {
	t.Helper()
	tpl, err := template.New("pages").Parse(`
{{define "overrideForm.html"}}RL={{.RateLimit}};{{.FormHTML}}{{end}}
{{define "overrideSuccess.html"}}ok{{end}}
`)
	if err != nil {
		t.Errorf("parse templates: %s", err)
	}
	return tpl
}

func TestSetOverrideRequestFormHeaders(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	setOverrideRequestFormHeaders(rec)

	h := rec.Header()
	got := h.Get("X-Frame-Options")
	if got != "DENY" {
		t.Errorf("Unexpected X-Frame-Options=%q, expected Unexpected X-Frame-Options=\"DENY\"", got)
	}
	csp := h.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self' https:") ||
		!strings.Contains(csp, "script-src 'self'") ||
		!strings.Contains(csp, "style-src 'self'") ||
		!strings.Contains(csp, "object-src 'none'") ||
		!strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("Unexpected Content-Security-Policy=%q", csp)
	}
	got = h.Get("Cross-Origin-Opener-Policy")
	if got != "same-origin" {
		t.Errorf("Unexpected COOP=%q, expected COOP=\"same-origin\"", got)
	}
	got = h.Get("Cross-Origin-Resource-Policy")
	if got != "same-site" {
		t.Errorf("Unexpected CORP=%q, expected CORP=\"same-site\"", got)
	}
	got = h.Get("Cache-Control")
	if !strings.Contains(got, "no-store") {
		t.Errorf("Unexpected Cache-Control=%q, expected Cache-Control=\"no-store\"", got)
	}
}

func TestValidateOverrideFieldHandlerBadJSON(t *testing.T) {
	t.Parallel()

	sfe, _ := setupSFE(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{"))

	sfe.validateOverrideFieldHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Unexpected status=%d; expected status=400", rec.Code)
	}
}

func TestValidateOverrideFieldHandlerInvalidValue(t *testing.T) {
	t.Parallel()

	sfe, _ := setupSFE(t)

	payload := validationRequest{
		RateLimit: rl.NewOrdersPerAccount.String(),
		Field:     emailAddressFieldName,
		Value:     "definitely-not-an-email",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Errorf("marshal: %s", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))

	sfe.validateOverrideFieldHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Unexpected status=%d, expected status=200", rec.Code)
	}
	var resp validationResponse
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	if err != nil {
		t.Errorf("Unexpected failure to unmarshal JSON validationResponse: %s", err)
	}
	if resp.Valid {
		t.Errorf("Valid=true; expect false")
	}
	if resp.Error == "" {
		t.Errorf("Error empty; expect message")
	}
}

func TestSubmitOverrideRequestHandlerErrors(t *testing.T) {
	t.Parallel()

	sfe, _ := setupSFE(t)
	sfe.templatePages = minimalTemplates(t)
	_, client := createFakeZendeskClientServer(t)
	sfe.zendeskClient = client
	mockSalesforceClient, mockImpl := mocks.NewMockSalesforceClientImpl()
	sfe.ee = mocks.NewMockExporterImpl(mockSalesforceClient)

	// Submit valid JSON with no rateLimit field.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"fields":{}}`))
	sfe.submitOverrideRequestHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("Missing ratelimit: status=%d; expect 400", rec.Code)
	}

	// Submit valid JSON with a valid registered domain AND a valid IPv4 address
	// when only one of these is allowed.
	body, err := json.Marshal(overrideRequest{
		RateLimit: rl.CertificatesPerDomain.String(), Fields: map[string]string{
			subscriberAgreementFieldName: "true",
			privacyPolicyFieldName:       "true",
			mailingListFieldName:         "false",
			fundraisingFieldName:         FundraisingOptions[0],
			emailAddressFieldName:        "foo@bar.co",
			OrganizationFieldName:        "Big Host Inc.",
			useCaseFieldName:             strings.Repeat("x", 60),
			TierFieldName:                certificatesPerDomainTierOptions[0],
			RegisteredDomainFieldName:    "bar.co",
			IPAddressFieldName:           "2606:4700:4700::1111",
		},
	})
	if err != nil {
		t.Errorf("Unexpected failure to marshal JSON overrideRequest: %s", err)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	sfe.submitOverrideRequestHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("Both domain and IP: status=%d; expect 400", rec.Code)
	}
	if len(mockImpl.GetCreatedContacts()) != 0 {
		t.Errorf("PardotClient.SendContact called unexpectedly")
	}
	if len(mockImpl.GetCreatedCases()) != 0 {
		t.Errorf("PardotClient.SendCase called unexpectedly")
	}
}

func TestSubmitOverrideRequestHandlerSuccess(t *testing.T) {
	t.Parallel()

	sfe, _ := setupSFE(t)
	sfe.templatePages = minimalTemplates(t)
	_, client := createFakeZendeskClientServer(t)
	sfe.zendeskClient = client

	// All of these fields are perfectly valid.
	testBase := map[string]string{
		subscriberAgreementFieldName: "true",
		privacyPolicyFieldName:       "true",
		mailingListFieldName:         "true",
		fundraisingFieldName:         FundraisingOptions[0],
		emailAddressFieldName:        "foo@bar.co",
		OrganizationFieldName:        "Big Host Inc.",
		useCaseFieldName:             strings.Repeat("x", 60),
		TierFieldName:                newOrdersPerAccountTierOptions[0],
	}

	type tc struct {
		name         string
		rateLimit    string
		fields       map[string]string
		zendeskMatch map[string]string
	}
	tests := []tc{
		{
			name:      "NewOrdersPerAccount with valid Account URI",
			rateLimit: rl.NewOrdersPerAccount.String(),
			fields: map[string]string{
				AccountURIFieldName: "https://acme-v02.api.letsencrypt.org/acme/acct/12345",
			},
			zendeskMatch: map[string]string{
				RateLimitFieldName:  rl.NewOrdersPerAccount.String(),
				AccountURIFieldName: "https://acme-v02.api.letsencrypt.org/acme/acct/12345",
			},
		},
		{
			name:      "CertificatesPerDomainPerAccount with valid Account URI",
			rateLimit: rl.CertificatesPerDomainPerAccount.String(),
			fields: map[string]string{
				TierFieldName:       certificatesPerDomainPerAccountTierOptions[0],
				AccountURIFieldName: "https://acme-v02.api.letsencrypt.org/acme/acct/67890",
			},
			zendeskMatch: map[string]string{
				RateLimitFieldName:  rl.CertificatesPerDomainPerAccount.String(),
				AccountURIFieldName: "https://acme-v02.api.letsencrypt.org/acme/acct/67890",
			},
		},
		{
			name:      "CertificatesPerDomain with valid Registered Domain",
			rateLimit: rl.CertificatesPerDomain.String() + perDNSNameSuffix,
			fields: map[string]string{
				TierFieldName:             certificatesPerDomainTierOptions[0],
				RegisteredDomainFieldName: "bar.co",
			},
			zendeskMatch: map[string]string{
				RateLimitFieldName:        rl.CertificatesPerDomain.String() + perDNSNameSuffix,
				RegisteredDomainFieldName: "bar.co",
			},
		},
		{
			name:      "CertificatesPerDomain with valid IPv6 Address",
			rateLimit: rl.CertificatesPerDomain.String() + perIPSuffix,
			fields: map[string]string{
				TierFieldName:      certificatesPerDomainTierOptions[0],
				IPAddressFieldName: "2606:4700:4700::1111",
			},
			zendeskMatch: map[string]string{
				RateLimitFieldName: rl.CertificatesPerDomain.String() + perIPSuffix,
				IPAddressFieldName: "2606:4700:4700::1111",
			},
		},
		{
			name:      "CertificatesPerDomain with valid IPv4 Address",
			rateLimit: rl.CertificatesPerDomain.String() + perIPSuffix,
			fields: map[string]string{
				TierFieldName:      certificatesPerDomainTierOptions[0],
				IPAddressFieldName: "64.112.11.11",
			},
			zendeskMatch: map[string]string{
				RateLimitFieldName: rl.CertificatesPerDomain.String() + perIPSuffix,
				IPAddressFieldName: "64.112.11.11",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSalesforceClient, mockImpl := mocks.NewMockSalesforceClientImpl()
			sfe.ee = mocks.NewMockExporterImpl(mockSalesforceClient)

			iterationBase := map[string]string{}
			maps.Copy(iterationBase, testBase)
			maps.Copy(iterationBase, tt.fields)

			reqObj := overrideRequest{
				RateLimit: tt.rateLimit,
				Fields:    iterationBase,
			}
			body, err := json.Marshal(reqObj)
			if err != nil {
				t.Errorf("marshal: %s", err)
			}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))

			sfe.submitOverrideRequestHandler(rec, req)

			if rec.Code != http.StatusAccepted {
				t.Errorf("Unexpected status=%d, expected status=202", rec.Code)
			}

			got, err := client.FindTickets(tt.zendeskMatch, "")
			if err != nil {
				t.Errorf("FindTickets(%+v) returned error: %s", tt.zendeskMatch, err)
			}
			if len(got) == 0 {
				t.Errorf("FindTickets(%+v) returned no tickets, should have found one", tt.zendeskMatch)
			}
			for _, fields := range got {
				for fieldName, fieldValue := range tt.zendeskMatch {
					_, ok := fields[fieldName]
					if !ok {
						t.Errorf("The resulting ticket is missing expected field %q in %+v", fieldName, fields)
					}
					if fields[fieldName] != fieldValue {
						t.Errorf("The resulting ticket is missing an expected field value %q=%q in %+v", fieldName, fieldValue, fields)
					}
				}
				break
			}
			if len(mockImpl.GetCreatedContacts()) != 1 {
				t.Errorf("PardotClient.SendContact not called exactly once")
			}
			if len(mockImpl.GetCreatedCases()) != 1 {
				t.Errorf("PardotClient.SendCase not called exactly once")
			}
		})
	}
}

func TestValidateOverrideRequestField(t *testing.T) {
	type testCase struct {
		name              string
		fieldName         string
		fieldValue        string
		ratelimitName     string
		expectErr         bool
		expectErrContains string
	}

	var cases []testCase
	// Empty Field
	cases = append(cases,
		testCase{"Empty field name", "", "x", "rl", true, "field name cannot be empty"},
		testCase{"Empty field value", "some", "", "rl", true, "cannot be empty"},
		testCase{"Tier without rate limit", TierFieldName, "10", "", true, "must be specified"},
		testCase{"Unknown field", "not-a-field", "x", "rl", true, "unknown field"},
	)
	// MailingListFieldName
	cases = append(cases,
		testCase{"MailingList true", mailingListFieldName, "true", "", false, ""},
		testCase{"MailingList false", mailingListFieldName, "false", "", false, ""},
		testCase{"MailingList yup", mailingListFieldName, "yup", "", true, "true or false"},
	)
	// SubscriberAgreement/PrivacyPolicy
	for _, fieldName := range []string{subscriberAgreementFieldName, privacyPolicyFieldName} {
		cases = append(cases,
			testCase{fieldName + " true", fieldName, "true", "", false, ""},
			testCase{fieldName + " false", fieldName, "false", "", true, "required"},
			testCase{fieldName + " yep", fieldName, "yep", "", true, "true or false"},
		)
	}
	// FundraisingFieldName
	cases = append(cases,
		testCase{"Fundraising valid", fundraisingFieldName, FundraisingOptions[0], "", false, ""},
		testCase{"Fundraising invalid", fundraisingFieldName, "explicitly not an option", "", true, "valid options are"},
	)
	// EmailAddressFieldName
	cases = append(cases,
		testCase{"EmailAddress valid email", emailAddressFieldName, "foo@bar.co", "", false, ""},
		testCase{"EmailAddress invalid", emailAddressFieldName, "foo@", "", true, "invalid"},
	)
	// OrganizationFieldName
	cases = append(cases,
		testCase{"Organization valid", OrganizationFieldName, "Big Host Inc", "", false, ""},
		testCase{"Organization too short", OrganizationFieldName, "Big", "", true, "at least five"},
	)
	// UseCaseFieldName
	cases = append(cases,
		testCase{"UseCase exactly long enough", useCaseFieldName, strings.Repeat("x", 60), "", false, ""},
		testCase{"UseCase too short", useCaseFieldName, strings.Repeat("x", 59), "", true, "at least 60"},
	)
	// IPAddressFieldName
	cases = append(cases,
		testCase{"IPAddress IPv4 valid", IPAddressFieldName, "64.112.11.11", "", false, ""},
		testCase{"IPAddress IPv4 invalid", IPAddressFieldName, "64.112.11.256", "", true, "invalid"},
		testCase{"IPAddress IPv6 valid", IPAddressFieldName, "2606:4700:4700::1111", "", false, ""},
		testCase{"IPAddress IPv6 invalid", IPAddressFieldName, "2606:4700:4700::1111:12345", "", true, "invalid"},
	)
	// RegisteredDomainFieldName
	cases = append(cases,
		testCase{"RegisteredDomain valid eTLD+1", RegisteredDomainFieldName, "example.com", "", false, ""},
		testCase{"RegisteredDomain bare TLD", RegisteredDomainFieldName, "com", "", true, "registered domain name is invalid"},
		testCase{"RegisteredDomain eTLD+2", RegisteredDomainFieldName, "foo.bar.example.com", "", true, "only the eTLD+1"},
		testCase{"RegisteredDomain invalid syntax", RegisteredDomainFieldName, "not even close to a domain", "", true, "invalid"},
	)
	// AccountURIFieldName
	cases = append(cases,
		testCase{"AccountURI valid", AccountURIFieldName, "https://acme-v02.api.letsencrypt.org/acme/acct/12345", "", false, ""},
		testCase{"AccountURI bad host", AccountURIFieldName, "https://acme-v02.ap1.letsencrypt.org/acme/acct/1", "", true, "account URI is invalid"},
		testCase{"AccountURI bad id", AccountURIFieldName, "https://acme-v02.api.letsencrypt.org/acme/acct/notnum", "", true, "positive integer"},
		testCase{"AccountURI bad path shape", AccountURIFieldName, "https://acme-v02.api.letsencrypt.org/acme/acct/1/extra", "", true, "path must be"},
	)
	// TierFieldName
	cases = append(cases,
		testCase{"Tier valid", TierFieldName, "1000", "NewOrdersPerAccount", false, ""},
		testCase{"Tier invalid option", TierFieldName, "999", "NewOrdersPerAccount", true, "valid options are"},
		testCase{"Tier unknown rl", TierFieldName, "10", "DoesNotExist", true, "unknown rate limit"},
	)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOverrideRequestField(tc.fieldName, tc.fieldValue, tc.ratelimitName)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.expectErrContains != "" && !strings.Contains(err.Error(), tc.expectErrContains) {
					t.Fatalf("Error %q does not contain %q", err.Error(), tc.expectErrContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error, got %s", err)
			}
		})
	}
}

func TestSubmitOverrideRequestHandlerRateLimited(t *testing.T) {
	t.Parallel()

	sfe, _ := setupSFE(t)
	sfe.templatePages = minimalTemplates(t)
	_, client := createFakeZendeskClientServer(t)
	sfe.zendeskClient = client

	for attempt := range 101 {
		reqObj := overrideRequest{
			RateLimit: rl.CertificatesPerDomainPerAccount.String(),
			Fields: map[string]string{
				subscriberAgreementFieldName: "true",
				privacyPolicyFieldName:       "true",
				mailingListFieldName:         "false",
				fundraisingFieldName:         FundraisingOptions[0],
				emailAddressFieldName:        "foo@bar.co",
				OrganizationFieldName:        "Big Host Inc.",
				useCaseFieldName:             strings.Repeat("x", 60),
				TierFieldName:                certificatesPerDomainPerAccountTierOptions[0],
				AccountURIFieldName:          "https://acme-v02.api.letsencrypt.org/acme/acct/67890",
			},
		}
		body, err := json.Marshal(reqObj)
		if err != nil {
			t.Errorf("Unexpected failure to marshal JSON overrideRequest: %s", err)
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))

		sfe.submitOverrideRequestHandler(rec, req)
		if attempt < 100 {
			if rec.Code != http.StatusAccepted {
				t.Errorf("Unexpected status=%d, expected status=202", rec.Code)
			}
		} else {
			if rec.Code != http.StatusTooManyRequests {
				t.Errorf("Unexpected status=%d, expected status=429", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), "too many override request form submissions (100)") {
				t.Errorf("Expected rate limit error message, got: %s", rec.Body.String())
			}
		}
	}
}

type addedOverrideEnabledRA struct {
	rapb.RegistrationAuthorityClient
}

func (f *addedOverrideEnabledRA) AddRateLimitOverride(ctx context.Context, req *rapb.AddRateLimitOverrideRequest, opts ...grpc.CallOption) (*rapb.AddRateLimitOverrideResponse, error) {
	return &rapb.AddRateLimitOverrideResponse{Enabled: true}, nil
}

type addedOverrideDisabledRA struct {
	rapb.RegistrationAuthorityClient
}

func (f *addedOverrideDisabledRA) AddRateLimitOverride(ctx context.Context, req *rapb.AddRateLimitOverrideRequest, opts ...grpc.CallOption) (*rapb.AddRateLimitOverrideResponse, error) {
	return &rapb.AddRateLimitOverrideResponse{Enabled: false}, nil
}

func TestSubmitOverrideRequestHandlerAutoApproved(t *testing.T) {
	t.Parallel()

	sfe, _ := setupSFE(t)
	sfe.templatePages = minimalTemplates(t)
	_, client := createFakeZendeskClientServer(t)
	sfe.zendeskClient = client
	sfe.autoApproveOverrides = true

	reqObj := overrideRequest{
		RateLimit: rl.CertificatesPerDomainPerAccount.String(),
		Fields: map[string]string{
			subscriberAgreementFieldName: "true",
			privacyPolicyFieldName:       "true",
			mailingListFieldName:         "false",
			fundraisingFieldName:         FundraisingOptions[0],
			emailAddressFieldName:        "foo@bar.co",
			OrganizationFieldName:        "Big Host Inc.",
			useCaseFieldName:             strings.Repeat("x", 60),
			TierFieldName:                certificatesPerDomainPerAccountTierOptions[0],
			AccountURIFieldName:          "https://acme-v02.api.letsencrypt.org/acme/acct/67890",
		},
	}
	reqObjBytes, err := json.Marshal(reqObj)
	if err != nil {
		t.Fatalf("marshal: %s", err)
	}

	type testCase struct {
		name         string
		ra           rapb.RegistrationAuthorityClient
		expectedCode int
	}
	cases := []testCase{
		{
			name:         "New override enabled",
			ra:           &addedOverrideEnabledRA{},
			expectedCode: http.StatusCreated,
		},
		{
			name:         "Existing override disabled",
			ra:           &addedOverrideDisabledRA{},
			expectedCode: http.StatusAccepted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {

			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(reqObjBytes))
			rec := httptest.NewRecorder()

			sfe.ra = tc.ra
			sfe.submitOverrideRequestHandler(rec, req)

			if rec.Code != tc.expectedCode {
				t.Errorf("Unexpected status=%d, expected status=%d", rec.Code, tc.expectedCode)
			}
		})
	}
}
