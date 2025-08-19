package sfe

import (
	"bytes"
	"encoding/json"
	"html/template"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	rl "github.com/letsencrypt/boulder/ratelimits"
	rlo "github.com/letsencrypt/boulder/ratelimits/overriderequests"
	"github.com/letsencrypt/boulder/sfe/zendesk"
	"github.com/letsencrypt/boulder/test/zendeskfake"
)

const (
	apiTokenEmail = "tester@example.com"
	apiToken      = "someToken"
)

func createFakeZendeskClientServer(t *testing.T) *zendesk.Client {
	t.Helper()

	ts := httptest.NewServer(zendeskfake.NewServer(apiTokenEmail, apiToken, nil).Handler())
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
	return client
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

func TestValidateOverrideFieldHandlerMethodNotAllowed(t *testing.T) {
	t.Parallel()

	sfe, _ := setupSFE(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	sfe.validateOverrideFieldHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status=%d; expect 405", rec.Code)
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
		Field:     rlo.EmailAddressFieldName,
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
	client := createFakeZendeskClientServer(t)
	sfe.zendeskClient = client

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
			rlo.SubscriberAgreementFieldName: "true",
			rlo.PrivacyPolicyFieldName:       "true",
			rlo.MailingListFieldName:         "false",
			rlo.FundraisingFieldName:         rlo.FundraisingOptions[0],
			rlo.EmailAddressFieldName:        "foo@bar.co",
			rlo.OrganizationFieldName:        "Big Host Inc.",
			rlo.UseCaseFieldName:             strings.Repeat("x", 60),
			rlo.TierFieldName:                rlo.CertificatesPerDomainTiers[0],
			rlo.RegisteredDomainFieldName:    "bar.co",
			rlo.IPAddressFieldName:           "2606:4700:4700::1111",
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
}

func TestSubmitOverrideRequestHandlerSuccess(t *testing.T) {
	t.Parallel()

	sfe, _ := setupSFE(t)
	sfe.templatePages = minimalTemplates(t)
	client := createFakeZendeskClientServer(t)
	sfe.zendeskClient = client

	// All of these fields are perfectly valid.
	testBase := map[string]string{
		rlo.SubscriberAgreementFieldName: "true",
		rlo.PrivacyPolicyFieldName:       "true",
		rlo.MailingListFieldName:         "false",
		rlo.FundraisingFieldName:         rlo.FundraisingOptions[0],
		rlo.EmailAddressFieldName:        "foo@bar.co",
		rlo.OrganizationFieldName:        "Big Host Inc.",
		rlo.UseCaseFieldName:             strings.Repeat("x", 60),
		rlo.TierFieldName:                rlo.NewOrdersPerAccountTiers[0],
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
				rlo.AccountURIFieldName: "https://acme-v02.api.letsencrypt.org/acme/acct/12345",
			},
			zendeskMatch: map[string]string{
				rlo.RateLimitFieldName:  rl.NewOrdersPerAccount.String(),
				rlo.AccountURIFieldName: "https://acme-v02.api.letsencrypt.org/acme/acct/12345",
			},
		},
		{
			name:      "CertificatesPerDomainPerAccount with valid Account URI",
			rateLimit: rl.CertificatesPerDomainPerAccount.String(),
			fields: map[string]string{
				rlo.TierFieldName:       rlo.CertificatesPerDomainPerAccountTiers[0],
				rlo.AccountURIFieldName: "https://acme-v02.api.letsencrypt.org/acme/acct/67890",
			},
			zendeskMatch: map[string]string{
				rlo.RateLimitFieldName:  rl.CertificatesPerDomainPerAccount.String(),
				rlo.AccountURIFieldName: "https://acme-v02.api.letsencrypt.org/acme/acct/67890",
			},
		},
		{
			name:      "CertificatesPerDomain with valid Registered Domain",
			rateLimit: rl.CertificatesPerDomain.String(),
			fields: map[string]string{
				rlo.TierFieldName:             rlo.CertificatesPerDomainTiers[0],
				rlo.RegisteredDomainFieldName: "bar.co",
			},
			zendeskMatch: map[string]string{
				rlo.RateLimitFieldName:        rl.CertificatesPerDomain.String(),
				rlo.RegisteredDomainFieldName: "bar.co",
			},
		},
		{
			name:      "CertificatesPerDomain with valid IPv6 Address",
			rateLimit: rl.CertificatesPerDomain.String(),
			fields: map[string]string{
				rlo.TierFieldName:      rlo.CertificatesPerDomainTiers[0],
				rlo.IPAddressFieldName: "2606:4700:4700::1111",
			},
			zendeskMatch: map[string]string{
				rlo.RateLimitFieldName: rl.CertificatesPerDomain.String(),
				rlo.IPAddressFieldName: "2606:4700:4700::1111",
			},
		},
		{
			name:      "CertificatesPerDomain with valid IPv4 Address",
			rateLimit: rl.CertificatesPerDomain.String(),
			fields: map[string]string{
				rlo.TierFieldName:      rlo.CertificatesPerDomainTiers[0],
				rlo.IPAddressFieldName: "64.112.11.11",
			},
			zendeskMatch: map[string]string{
				rlo.RateLimitFieldName: rl.CertificatesPerDomain.String(),
				rlo.IPAddressFieldName: "64.112.11.11",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

			if rec.Code != http.StatusOK {
				t.Errorf("Unexpected status=%d, expected status=200", rec.Code)
			}

			got, err := client.FindTickets(tt.zendeskMatch)
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
		})
	}
}
