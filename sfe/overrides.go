package sfe

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	rl "github.com/letsencrypt/boulder/ratelimits"
	rlo "github.com/letsencrypt/boulder/ratelimits/overriderequests"
	"github.com/letsencrypt/boulder/sfe/forms"
)

var (
	fundraisingField = forms.NewDropdownField(
		"Did you know that Let's Encrypt is a non-profit project?",
		rlo.FundraisingFieldName,
		`Funding for Let's Encrypt comes from contributions from our community 
of users and advocates. While financially supporting Let's Encrypt is completely 
optional and not required to use the service, we depend on the generosity of users 
like you.

Would your organization consider financially supporting Let's Encrypt as a Sponsor?`,
		rlo.FundraisingOptions,
		true,
	)
	base = forms.NewBaseOverrideForm(
		forms.NewCheckboxField(
			"Subscriber Agreement",
			rlo.SubscriberAgreementFieldName,
			`I acknowledge that I have read and agree to the latest version of the
<a href="https://letsencrypt.org/repository">Let's Encrypt Subscriber Agreement</a>
and understand that my use of Let's Encrypt services is subject to its terms.`,
			true,
		),
		forms.NewCheckboxField(
			"Privacy Policy",
			rlo.PrivacyPolicyFieldName,
			`By submitting this form, I acknowledge that the information provided will be
processed in accordance with <a href="https://letsencrypt.org/privacy">Let's
Encrypt's Privacy Policy</a>. I understand that ISRG collects and will process
this information to evaluate your rate limit override request and to provide
certificate issuance and management services. In addition, depending on your
responses to questions below, ISRG may use this information to send email
updates and sponsorship information to you.`,
			true,
		),
		forms.NewCheckboxField(
			"Mailing List",
			rlo.MailingListFieldName,
			"Subscribe to email updates about Let's Encrypt and other ISRG Projects.",
			false,
		),
		forms.NewTextareaField(
			"Use Case",
			rlo.UseCaseFieldName,
			`Please describe the use case for this override request. This helps us
understand the need for the override and how it will be used.`,
			4,
			true,
		),
		forms.NewInputField(
			"Email Address",
			rlo.EmailAddressFieldName,
			`An email address where we can reach you regarding this request.`,
			true,
		),
		forms.NewInputField(
			"Organization or Project",
			rlo.OrganizationFieldName,
			`This helps us understand who is requesting the override and find the right
contact person if needed.`,
			true,
		),
	).RenderForm()

	newOrdersPerAccountForm = base + forms.NewNewOrdersPerAccountOverrideForm(
		forms.NewDropdownField(
			"Maximum Orders Per Week",
			rlo.TierFieldName,
			`The number of orders per week needed for this account. Please select the
number that best matches your needs.`,
			rlo.NewOrdersPerAccountTiers,
			true,
		),
		forms.NewInputField(
			"Account URI",
			rlo.AccountURIFieldName,
			`The ACME account URI you're requesting the override for. For example:
https://acme-v02.api.letsencrypt.org/acme/acct/12345. Read more about Account
IDs <a href="https://letsencrypt.org/docs/account-id">here</a>.`,
			true,
		),
	).RenderForm()

	certificatesPerDomainForm = base + forms.NewCertificatesPerDomainOverrideForm(
		forms.NewDropdownField(
			"Maximum Certificates Per Week",
			rlo.TierFieldName,
			`The number of certificates per week needed for this domain and all
subdomains. Please select the number that best matches your needs.`,
			rlo.CertificatesPerDomainTiers,
			true,
		),
		forms.NewInputField(
			"Registered Domain Name",
			rlo.RegisteredDomainFieldName,
			`The registered domain name you're requesting the override for. This should
be the base domain, for instance, example.com, not www.example.com or
blog.example.com. For Internationalized Domain Names such as bücher.com, use the
<a href="https://www.punycoder.com/">ASCII-compatible Punycode</a> form:
xn--bcher-kva.com.`,
			true,
		),
	).RenderForm()

	certificatesPerDomainPerAccountForm = base + forms.NewCertificatesPerDomainPerAccountOverrideForm(
		forms.NewDropdownField(
			"Maximum Certificates Per Week",
			rlo.TierFieldName,
			`The number of certificates per week per registered domain name or IP
address included in certificates requested by this account. Please select the
number that best matches your needs.`,
			rlo.CertificatesPerDomainPerAccountTiers,
			true,
		),
		forms.NewInputField(
			"Account URI",
			rlo.AccountURIFieldName,
			`The account URI you're requesting the override for, for example:
https://acme-v02.api.letsencrypt.org/acme/acct/12345.`,
			true,
		),
	).RenderForm()

	certificatesPerIPForm = base + forms.NewCertificatesPerIPOverrideForm(
		forms.NewDropdownField(
			"Maximum Certificates Per Week",
			rlo.TierFieldName,
			`The number of certificates per week needed for this IP address. Please
select the number that best matches your needs.`,
			rlo.CertificatesPerDomainTiers,
			true,
		),
		forms.NewInputField(
			"IP Address",
			rlo.IPAddressFieldName,
			`The IPv4 or IPv6 address you're requesting the override for. This should
be the public IP address included in the certificate itself.`,
			true,
		),
	).RenderForm()
)

func setOverrideRequestFormHeaders(w http.ResponseWriter) {
	// Prevent this page from being embedded in a frame/iframe to mitigate
	// clickjacking.
	w.Header().Set("X-Frame-Options", "DENY")

	w.Header().Set("Content-Security-Policy", strings.Join([]string{
		// Only allow same-origin and HTTPS subresources by default.
		"default-src 'self' https:",
		// Only allow scripts from same-origin (no inline/eval).
		"script-src 'self'",
		// Only allow stylesheets from same-origin.
		"style-src 'self'",
		// Block legacy plugin content (<object>, <embed>, <applet>).
		"object-src 'none'",
		// Do not allow any site to frame this page.
		"frame-ancestors 'none'",
	}, "; "))

	// Mitigates cross-origin window references/leaks.
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")

	// Restrict other sites from embedding/fetching this resource.
	w.Header().Set("Cross-Origin-Resource-Policy", "same-site")

	// Prevent caching of this page and its responses.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

const (
	overrideFormTemplate = "overrideForm.html"
	formHTMLKey          = "FormHTML"
	rateLimitKey         = "RateLimit"
	validateFieldPathKey = "ValidateFieldPath"
	submitRequestPathKey = "SubmitRequestPath"
	submitSuccessPathKey = "SubmitSuccessPath"
)

// NewOrdersPerAccountOverrideRequestHandler renders the Web UI for the
// NewOrdersPerAccount override request form.
func (sfe *SelfServiceFrontEndImpl) newOrderPerAccountOverrideRequestHandler(w http.ResponseWriter, r *http.Request) {
	setOverrideRequestFormHeaders(w)
	sfe.renderTemplate(w, overrideFormTemplate, map[string]any{
		formHTMLKey:          newOrdersPerAccountForm + fundraisingField.RenderField(),
		rateLimitKey:         rl.NewOrdersPerAccount.String(),
		validateFieldPathKey: overridesValidateField,
		submitRequestPathKey: overridesSubmitRequest,
		submitSuccessPathKey: overridesSubmitSuccess,
	})
}

// certificatesPerDomainOverrideRequestHandler renders the Web UI for the
// CertificatesPerDomain override request form.
func (sfe *SelfServiceFrontEndImpl) certificatesPerDomainOverrideRequestHandler(w http.ResponseWriter, r *http.Request) {
	setOverrideRequestFormHeaders(w)
	sfe.renderTemplate(w, overrideFormTemplate, map[string]any{
		formHTMLKey:          certificatesPerDomainForm + fundraisingField.RenderField(),
		rateLimitKey:         rl.CertificatesPerDomain.String(),
		validateFieldPathKey: overridesValidateField,
		submitRequestPathKey: overridesSubmitRequest,
		submitSuccessPathKey: overridesSubmitSuccess,
	})
}

// certificatesPerIPOverrideRequestHandler renders the Web UI for the
// CertificatesPerDomain override request form specific to IP addresses.
func (sfe *SelfServiceFrontEndImpl) certificatesPerIPOverrideRequestHandler(w http.ResponseWriter, r *http.Request) {
	setOverrideRequestFormHeaders(w)
	sfe.renderTemplate(w, overrideFormTemplate, map[string]any{
		formHTMLKey:          certificatesPerIPForm + fundraisingField.RenderField(),
		rateLimitKey:         rl.CertificatesPerDomain.String(),
		validateFieldPathKey: overridesValidateField,
		submitRequestPathKey: overridesSubmitRequest,
		submitSuccessPathKey: overridesSubmitSuccess,
	})
}

// certificatesPerDomainPerAccountOverrideRequestHandler renders the Web UI for
// the CertificatesPerDomainPerAccount override request form.
func (sfe *SelfServiceFrontEndImpl) certificatesPerDomainPerAccountOverrideRequestHandler(w http.ResponseWriter, r *http.Request) {
	setOverrideRequestFormHeaders(w)
	sfe.renderTemplate(w, overrideFormTemplate, map[string]any{
		formHTMLKey:          certificatesPerDomainPerAccountForm + fundraisingField.RenderField(),
		rateLimitKey:         rl.CertificatesPerDomainPerAccount.String(),
		validateFieldPathKey: overridesValidateField,
		submitRequestPathKey: overridesSubmitRequest,
		submitSuccessPathKey: overridesSubmitSuccess,
	})
}

type validationRequest struct {
	RateLimit string `json:"rateLimit"`
	Field     string `json:"field"`
	Value     string `json:"value"`
}

type validationResponse struct {
	Field string `json:"field"`
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

func (sfe *SelfServiceFrontEndImpl) validateOverrideFieldHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req validationRequest
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req)
	if err != nil {
		sfe.log.Errf("failed to decode validation request: %s", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var valid bool
	var message string
	err = rlo.ValidateOverrideRequestField(req.Field, req.Value, req.RateLimit)
	if err == nil {
		valid = true
	} else {
		message = err.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(validationResponse{
		Field: req.Field,
		Valid: valid,
		Error: message,
	})
	if err != nil {
		sfe.log.Errf("failed to encode validation response: %s", err)
		http.Error(w, "failed to encode validation response", http.StatusInternalServerError)
		return
	}
}

func (sfe *SelfServiceFrontEndImpl) overrideSuccessHandler(w http.ResponseWriter, r *http.Request) {
	sfe.renderTemplate(w, "overrideSuccess.html", nil)
}

type overrideRequest struct {
	RateLimit string            `json:"rateLimit"`
	Fields    map[string]string `json:"fields"`
}

// submitOverrideRequestHandler handles the submission of override requests. It
// expects a POST request with a JSON payload (overrideRequest). It validates
// each of the form fields and creates a Zendesk ticket based on the specified
// rate limit. If the request is successful it renders "overrideSuccess.html".
//
// The JavaScript frontend is configured to validate the form fields twice: once
// when the requester inputs data, and once more just before submitting the
// form. Any validation errors returned by this handler are an indication that
// either the form logic is flawed or the requester has bypassed the JavaScript
// validation and submitted invalid data directly to this endpoint.
func (sfe *SelfServiceFrontEndImpl) submitOverrideRequestHandler(w http.ResponseWriter, r *http.Request) {
	// TODO(#8359): Check per-IP rate limits for this endpoint.

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req overrideRequest
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&req)
	if err != nil {
		sfe.log.Errf("failed to decode override request: %s", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.RateLimit == "" {
		http.Error(w, "rate limit not specified", http.StatusBadRequest)
		return
	}

	getRaw := func(name string) string {
		return strings.TrimSpace(req.Fields[name])
	}
	getValidated := func(name string) (string, error) {
		val := getRaw(name)
		err := rlo.ValidateOverrideRequestField(name, val, req.RateLimit)
		if err != nil {
			return "", fmt.Errorf("invalid field %q: %w", name, err)
		}
		return val, nil
	}

	var baseFields = make(map[string]string)
	for _, name := range []string{
		// Note: not all of these fields will be included in the Zendesk ticket,
		// but they are all required for the submission to be considered valid.
		rlo.SubscriberAgreementFieldName,
		rlo.PrivacyPolicyFieldName,
		rlo.MailingListFieldName,
		rlo.FundraisingFieldName,
		rlo.EmailAddressFieldName,
		rlo.OrganizationFieldName,
		rlo.UseCaseFieldName,
		rlo.TierFieldName,
	} {
		val, err := getValidated(name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		baseFields[name] = val
	}

	switch req.RateLimit {
	case rl.NewOrdersPerAccount.String():
		accountURI, err := getValidated(rlo.AccountURIFieldName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// TODO(#8360): Skip ticket creation and insert an override for
		// overrides matching the first N tiers of this limit.

		_, err = rlo.CreateNewOrdersPerAccountOverrideTicket(
			sfe.zendeskClient,
			baseFields[rlo.EmailAddressFieldName],
			baseFields[rlo.UseCaseFieldName],
			baseFields[rlo.OrganizationFieldName],
			baseFields[rlo.TierFieldName],
			accountURI,
		)
		if err != nil {
			sfe.log.Errf("failed to create override request ticket: %s", err)
			http.Error(w, "failed to create override request ticket", http.StatusInternalServerError)
			return
		}

	case rl.CertificatesPerDomainPerAccount.String():
		accountURI, err := getValidated(rlo.AccountURIFieldName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// TODO(#8360): Skip ticket creation and insert an override for
		// overrides matching the first N tiers of this limit.

		_, err = rlo.CreateCertificatesPerDomainPerAccountOverrideTicket(
			sfe.zendeskClient,
			baseFields[rlo.EmailAddressFieldName],
			baseFields[rlo.UseCaseFieldName],
			baseFields[rlo.OrganizationFieldName],
			baseFields[rlo.TierFieldName],
			accountURI,
		)
		if err != nil {
			sfe.log.Errf("failed to create override request ticket: %s", err)
			http.Error(w, "failed to create override request ticket", http.StatusInternalServerError)
			return
		}

	case rl.CertificatesPerDomain.String():
		// We offer two different forms for the same rate limit here. One
		// expects an eTLD+1 and the other expects an IP address. One of these
		// fields will be empty, figure out which one was provided before
		// attempting to validate it.
		regDomain := getRaw(rlo.RegisteredDomainFieldName)
		ip := getRaw(rlo.IPAddressFieldName)
		if (regDomain == "") == (ip == "") {
			http.Error(
				w,
				fmt.Sprintf("provide either %q or %q (but not both)", rlo.RegisteredDomainFieldName, rlo.IPAddressFieldName),
				http.StatusBadRequest,
			)
			return
		}

		domainOrIP := rlo.RegisteredDomainFieldName
		if regDomain == "" {
			domainOrIP = rlo.IPAddressFieldName
		}
		_, err = getValidated(domainOrIP)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// TODO(#8360): Skip ticket creation and insert an override for
		// overrides matching the first N tiers of this limit.

		_, err = rlo.CreateCertificatesPerDomainOverrideTicket(
			sfe.zendeskClient,
			baseFields[rlo.EmailAddressFieldName],
			baseFields[rlo.UseCaseFieldName],
			baseFields[rlo.OrganizationFieldName],
			baseFields[rlo.TierFieldName],
			regDomain,
			ip,
		)
		if err != nil {
			sfe.log.Errf("failed to create override request ticket: %s", err)
			http.Error(w, "failed to create override request ticket", http.StatusInternalServerError)
			return
		}

	default:
		http.Error(w, "unknown rate limit", http.StatusBadRequest)
		return
	}

	// TODO(#8363): If MailingListFieldName value is true, dispatch a request to
	// the Salesforce Pardot email exporter.

	// TODO(#8362): If FundraisingFieldName value is true, use the Salesforce
	// API to create a new Lead record with the provided information.

	w.WriteHeader(http.StatusOK)
}
