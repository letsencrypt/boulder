package sfe

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/letsencrypt/boulder/iana"
	"github.com/letsencrypt/boulder/policy"
	rl "github.com/letsencrypt/boulder/ratelimits"
	"github.com/letsencrypt/boulder/sfe/forms"
	"github.com/letsencrypt/boulder/sfe/zendesk"
)

const (
	apiVersion         = "v1"
	overridesAPIPrefix = "/sfe/" + apiVersion

	// Meta fields (not user-entered)
	ReviewStatusFieldName = "reviewStatus"
	RateLimitFieldName    = "rateLimit"

	// Shared user-entered fields (UI + API/Zendesk)
	OrganizationFieldName     = "organization"
	TierFieldName             = "tier"
	AccountURIFieldName       = "accountURI"
	RegisteredDomainFieldName = "registeredDomain"
	IPAddressFieldName        = "ipAddress"

	// UI-only fields
	subscriberAgreementFieldName = "subscriberAgreement"
	privacyPolicyFieldName       = "privacyPolicy"
	emailAddressFieldName        = "emailAddress"
	useCaseFieldName             = "useCase"
	fundraisingFieldName         = "fundraising"
	mailingListFieldName         = "mailingList"

	// reviewStatusDefault is the initial status of a ticket when created.
	reviewStatusDefault = "review-status-pending"

	// validateOverrideFieldBodyLimit is the maximum size of request body
	// accepted by validateOverrideFieldHandler. It should be large enough to
	// accommodate the JSON encoded validationRequest struct, but small enough
	// to avoid abuse.
	//
	// It is currently set to 5 KiB, which is more than enough for even the
	// longest "Use Case" field values.
	validateOverrideFieldBodyLimit = 5 << 10

	// validateOverrideFieldBodyLimit is the maximum size of request body
	// accepted by validateOverrideFieldHandler. It should be large enough to
	// accommodate the JSON encoded overrideRequest struct, but small enough to
	// avoid abuse.
	//
	// It is currently set to 10 KiB, which is more than enough for the expected
	// request size.
	submitOverrideRequestBodyLimit = 10 << 10

	// These are suffixes added to the rate limit names to differentiate between
	// two different forms that request overrides for CertificatesPerDomain.
	perDNSNameSuffix = "_dnsName"
	perIPSuffix      = "_ipAddr"
)

var (
	// NOTE: If you modify one of the tier slices below, ensure that you have
	// already updated the corresponding dropdown in the Zendesk dashboard.
	// Failing to do so will result in the override request form not being able
	// to process the request.

	// newOrdersPerAccountTierOptions is the list of valid tiers for the
	// NewOrdersPerAccount rate limit override requests.
	newOrdersPerAccountTierOptions = []string{"1000", "5000", "10000", "25000", "50000", "75000", "100000", "175000", "250000", "500000", "750000", "1000000"}

	// certificatesPerDomainTierOptions is the list of valid tiers for the
	// CertificatesPerDomain rate limit.
	certificatesPerDomainTierOptions = []string{"300", "1000", "5000", "10000", "25000", "50000", "75000", "100000", "175000", "250000", "500000", "1000000"}

	// certificatesPerDomainPerAccountTierOptions is the list of valid tiers for
	// the CertificatesPerDomainPerAccount rate limit override requests.
	certificatesPerDomainPerAccountTierOptions = []string{"300", "1000", "5000", "10000", "25000", "50000", "75000", "100000", "175000", "250000", "500000", "1000000", "1750000", "2500000"}

	// FundraisingOptions is the list of options for the fundraising field.
	FundraisingOptions = []string{
		"Yes, email me more information.",
		"No, not at this time.",
	}

	// tierOptionsByRateLimit maps rate limit names to their valid tiers.
	tierOptionsByRateLimit = map[string][]string{
		rl.NewOrdersPerAccount.String():                      newOrdersPerAccountTierOptions,
		rl.CertificatesPerDomain.String() + perDNSNameSuffix: certificatesPerDomainTierOptions,
		rl.CertificatesPerDomain.String() + perIPSuffix:      certificatesPerDomainTierOptions,
		rl.CertificatesPerDomainPerAccount.String():          certificatesPerDomainPerAccountTierOptions,
	}

	fundraisingField = forms.NewDropdownField(
		"Did you know that Let's Encrypt is a non-profit project?",
		fundraisingFieldName,
		`Funding for Let's Encrypt comes from contributions from our community 
of users and advocates. While financially supporting Let's Encrypt is completely 
optional and not required to use the service, we depend on the generosity of users 
like you.

Would your organization consider financially supporting Let's Encrypt as a Sponsor?`,
		FundraisingOptions,
		true,
	)

	baseFields = []forms.Field{
		forms.NewCheckboxField(
			"Subscriber Agreement",
			subscriberAgreementFieldName,
			`I acknowledge that I have read and agree to the latest version of the
<a href="https://letsencrypt.org/repository">Let's Encrypt Subscriber Agreement</a>
and understand that my use of Let's Encrypt services is subject to its terms.`,
			true,
		),
		forms.NewCheckboxField(
			"Privacy Policy",
			privacyPolicyFieldName,
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
			mailingListFieldName,
			"Subscribe to email updates about Let's Encrypt and other ISRG Projects.",
			false,
		),
		forms.NewTextareaField(
			"Use Case",
			useCaseFieldName,
			`Please describe the use case for this override request. This helps us
understand the need for the override and how it will be used.`,
			4,
			true,
		),
		forms.NewInputField(
			"Email Address",
			emailAddressFieldName,
			`An email address where we can reach you regarding this request.`,
			true,
		),
		forms.NewInputField(
			"Organization or Project",
			OrganizationFieldName,
			`This helps us understand who is requesting the override and find the right
contact person if needed.`,
			true,
		),
	}
)

// overridesForm creates a new form with the base fields and the provided custom
// fields. The custom fields will appear after the baseFields and before the
// fundraising field.
func overridesForm(customFields ...forms.Field) *forms.Form {
	return forms.NewForm(append(append(baseFields, customFields...), fundraisingField)...)
}

var (
	newOrdersPerAccountForm = overridesForm(
		forms.NewDropdownField(
			"Maximum Orders Per Week",
			TierFieldName,
			`The number of orders per week needed for this account. Please select the
number that best matches your needs.`,
			newOrdersPerAccountTierOptions,
			true,
		),
		forms.NewInputField(
			"Account URI",
			AccountURIFieldName,
			`The ACME account URI you're requesting the override for. For example:
https://acme-v02.api.letsencrypt.org/acme/acct/12345. Read more about Account
IDs <a href="https://letsencrypt.org/docs/account-id">here</a>.`,
			true,
		),
	).RenderForm()

	certificatesPerDomainForm = overridesForm(
		forms.NewDropdownField(
			"Maximum Certificates Per Week",
			TierFieldName,
			`The number of certificates per week needed for this domain and all
subdomains. Please select the number that best matches your needs.`,
			certificatesPerDomainTierOptions,
			true,
		),
		forms.NewInputField(
			"Registered Domain Name",
			RegisteredDomainFieldName,
			`The registered domain name you're requesting the override for. This should
be the base domain, for instance, example.com, not www.example.com or
blog.example.com. For Internationalized Domain Names such as bücher.com, use the
<a href="https://www.punycoder.com/">ASCII-compatible Punycode</a> form:
xn--bcher-kva.com.`,
			true,
		),
	).RenderForm()

	certificatesPerDomainPerAccountForm = overridesForm(
		forms.NewDropdownField(
			"Maximum Certificates Per Week",
			TierFieldName,
			`The number of certificates per week per registered domain name or IP
address included in certificates requested by this account. Please select the
number that best matches your needs.`,
			certificatesPerDomainPerAccountTierOptions,
			true,
		),
		forms.NewInputField(
			"Account URI",
			AccountURIFieldName,
			`The account URI you're requesting the override for, for example:
https://acme-v02.api.letsencrypt.org/acme/acct/12345.`,
			true,
		),
	).RenderForm()

	certificatesPerIPForm = overridesForm(
		forms.NewDropdownField(
			"Maximum Certificates Per Week",
			TierFieldName,
			`The number of certificates per week needed for this IP address. Please
select the number that best matches your needs.`,
			certificatesPerDomainTierOptions,
			true,
		),
		forms.NewInputField(
			"IP Address",
			IPAddressFieldName,
			`The IPv4 or IPv6 address you're requesting the override for. This should
be the public IP address included in the certificate itself.`,
			true,
		),
	).RenderForm()
)

func makeSubject(rateLimit rl.Name, organization string) string {
	return fmt.Sprintf("%s rate limit override request for %s", rateLimit.String(), organization)
}

func makeInitialComment(organization, useCase, tier string) string {
	return fmt.Sprintf(
		"Use case: %s\n\nRequested Override Tier: %s\n\nOrganization: %s",
		useCase, tier, organization,
	)
}

// createNewOrdersPerAccountOverrideTicket creates a new Zendesk ticket for a
// NewOrdersPerAccount override request. All fields are required.
func createNewOrdersPerAccountOverrideTicket(client *zendesk.Client, requesterEmail, useCase, organization, tier, accountID string) (int64, error) {
	return client.CreateTicket(
		requesterEmail,
		makeSubject(rl.NewOrdersPerAccount, organization),
		makeInitialComment(organization, useCase, tier),
		map[string]string{
			RateLimitFieldName:    rl.NewOrdersPerAccount.String(),
			ReviewStatusFieldName: reviewStatusDefault,
			OrganizationFieldName: organization,
			TierFieldName:         tier,
			AccountURIFieldName:   accountID,
		},
	)
}

// createCertificatesPerDomainOverrideTicket creates a new Zendesk ticket for a
// CertificatesPerDomain override request. Only registeredDomain or ipAddress
// should be provided, not both. All other fields are required.
func createCertificatesPerDomainOverrideTicket(client *zendesk.Client, requesterEmail, useCase, organization, tier, registeredDomain, ipAddress string) (int64, error) {
	return client.CreateTicket(
		requesterEmail,
		makeSubject(rl.CertificatesPerDomain, organization),
		makeInitialComment(organization, useCase, tier),
		map[string]string{
			RateLimitFieldName:        rl.CertificatesPerDomain.String(),
			ReviewStatusFieldName:     reviewStatusDefault,
			OrganizationFieldName:     organization,
			TierFieldName:             tier,
			RegisteredDomainFieldName: registeredDomain,
			IPAddressFieldName:        ipAddress,
		},
	)
}

// createCertificatesPerDomainPerAccountOverrideTicket creates a new Zendesk
// ticket for a CertificatesPerDomainPerAccount override request. All fields are
// required.
func createCertificatesPerDomainPerAccountOverrideTicket(client *zendesk.Client, requesterEmail, useCase, organization, tier, accountID string) (int64, error) {
	return client.CreateTicket(
		requesterEmail,
		makeSubject(rl.CertificatesPerDomainPerAccount, organization),
		makeInitialComment(organization, useCase, tier),
		map[string]string{
			RateLimitFieldName:    rl.CertificatesPerDomainPerAccount.String(),
			ReviewStatusFieldName: reviewStatusDefault,
			OrganizationFieldName: organization,
			TierFieldName:         tier,
			AccountURIFieldName:   accountID,
		},
	)
}

// validateOverrideRequestField validates the provided field and value against
// the specified rate limit name. It returns nil if the field is valid, or an
// error if it is not.
func validateOverrideRequestField(fieldName, fieldValue, rateLimit string) error {
	if fieldName == "" {
		return fmt.Errorf("field name cannot be empty")
	}
	if fieldValue == "" {
		return fmt.Errorf("%q cannot be empty", fieldName)
	}
	if rateLimit == "" && fieldName == TierFieldName {
		return fmt.Errorf("a rate limit name must be specified")
	}

	switch fieldName {
	case mailingListFieldName:
		// This field is optional, so we only validate it is a boolean.
		if fieldValue != "true" && fieldValue != "false" {
			return fmt.Errorf("mailing list field must be true or false")
		}
		return nil

	case subscriberAgreementFieldName, privacyPolicyFieldName:
		agreed, err := strconv.ParseBool(fieldValue)
		if err != nil {
			return fmt.Errorf("subscriber agreement and privacy policy must be true or false")
		}
		if !agreed {
			return fmt.Errorf("agreement with our subscriber agreement and privacy policy is required")
		}
		return nil

	case fundraisingFieldName:
		if !slices.Contains(FundraisingOptions, fieldValue) {
			return fmt.Errorf("invalid fundraising option, valid options are: %s", strings.Join(FundraisingOptions, ", "))
		}
		return nil

	case emailAddressFieldName:
		err := policy.ValidEmail(fieldValue)
		if err == nil {
			return nil
		}
		return fmt.Errorf("email address is invalid")

	case OrganizationFieldName:
		if len(fieldValue) >= 5 {
			return nil
		}
		return fmt.Errorf("organization or project must be at least five (5) characters long")

	case useCaseFieldName:
		if len(fieldValue) >= 60 {
			return nil
		}
		return fmt.Errorf("use case must be at least 60 characters long")

	case IPAddressFieldName:
		err := policy.ValidIP(fieldValue)
		if err == nil {
			return nil
		}
		return fmt.Errorf("IP address is invalid")

	case RegisteredDomainFieldName:
		err := policy.ValidDomain(fieldValue)
		if err != nil {
			return fmt.Errorf("registered domain name is invalid")
		}
		suffix, err := iana.ExtractSuffix(fieldValue)
		if err != nil {
			return fmt.Errorf("registered domain name is invalid")
		}
		if fieldValue == suffix {
			return fmt.Errorf("registered domain name cannot be a bare top-level domain")
		}
		base := strings.TrimSuffix(fieldValue, "."+suffix)
		if base == "" || strings.Contains(base, ".") {
			return fmt.Errorf("only the eTLD+1 (e.g., example.com or example.co.uk) should be provided")
		}
		return nil

	case AccountURIFieldName:
		// Validation here is nuanced: we accept a well-formed Let's Encrypt
		// Account URI even though the prefix may vary. We don't store the URI
		// in the override; we only verify its shape and extract the Account ID.
		// Requesting this value in a format that most clients actually expose
		// allows us to reliably obtain a valid Account ID while ensuring the
		// URI targets Let's Encrypt rather than some other ACME CA.
		u, err := url.Parse(fieldValue)
		if err != nil {
			return fmt.Errorf("account URI is not a valid URL")
		}
		if !strings.HasSuffix(u.Host, "api.letsencrypt.org") || !strings.HasPrefix(u.Path, "/acme/acct/") {
			return fmt.Errorf("account URI is invalid")
		}
		segments := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(segments) != 3 || segments[0] != "acme" || segments[1] != "acct" {
			return fmt.Errorf("account URI path must be of the form /acme/acct/{id}")
		}
		_, err = strconv.ParseUint(segments[2], 10, 64)
		if err != nil {
			return fmt.Errorf("account ID must be a positive integer")
		}
		return nil

	case TierFieldName:
		valids, ok := tierOptionsByRateLimit[rateLimit]
		if !ok {
			return fmt.Errorf("unknown rate limit name: %s", rateLimit)
		}
		if slices.Contains(valids, fieldValue) {
			return nil
		}
		return fmt.Errorf("invalid request override quantity, valid options are: %s", strings.Join(valids, ", "))
	}
	return fmt.Errorf("unknown field %q", fieldName)
}

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

// makeOverrideRequestFormHandler is a wrapper around the overrideRequestHandler
// method that allows it to be used as an http.HandlerFunc.
func (sfe *SelfServiceFrontEndImpl) makeOverrideRequestFormHandler(formHTML template.HTML, rateLimit, displayRateLimit string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sfe.overrideRequestHandler(w, formHTML, rateLimit, displayRateLimit)
	}
}

// overrideRequestHandler renders the override request form with the specified
// form HTML and rate limit. RateLimit is the limit that will be used to
// validate the form fields when the user submits the form. RateLimitForDisplay
// is the limit that will be displayed to the user in the form. These are
// typically the same, but can differ in cases where multiple forms are used for
// the same rate limit.
func (sfe *SelfServiceFrontEndImpl) overrideRequestHandler(w http.ResponseWriter, formHTML template.HTML, rateLimit, displayRateLimit string) {
	setOverrideRequestFormHeaders(w)
	sfe.renderTemplate(w, "overrideForm.html", map[string]any{
		"FormHTML":          formHTML,
		"RateLimit":         rateLimit,
		"DisplayRateLimit":  displayRateLimit,
		"ValidateFieldPath": overridesValidateField,
		"SubmitRequestPath": overridesSubmitRequest,
		"SubmitSuccessPath": overridesSubmitSuccess,
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

// validateOverrideFieldHandler validates the provided field and value against
// the specified rate limit. It returns a JSON response indicating whether the
// field is valid, and an error message if it is not.
func (sfe *SelfServiceFrontEndImpl) validateOverrideFieldHandler(w http.ResponseWriter, r *http.Request) {
	var req validationRequest
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, validateOverrideFieldBodyLimit)).Decode(&req)
	if err != nil {
		sfe.log.Errf("failed to decode validation request: %s", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	valid := true
	var message string
	err = validateOverrideRequestField(req.Field, req.Value, req.RateLimit)
	if err != nil {
		valid = false
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

// overrideSuccessHandler renders the success page after a successful override
// request submission.
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
// rate limit. It returns a 200 OK response on success, or an error response if
// the request is invalid or if ticket creation fails.
//
// The JavaScript frontend is configured to validate the form fields twice: once
// when the requester inputs data, and once more just before submitting the
// form. Any validation errors returned by this handler are an indication that
// either the form logic is flawed or the requester has bypassed the form and
// submitting (malformed) requests directly to this endpoint.
func (sfe *SelfServiceFrontEndImpl) submitOverrideRequestHandler(w http.ResponseWriter, r *http.Request) {
	// TODO(#8359): Check per-IP rate limits for this endpoint.

	var req overrideRequest
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, submitOverrideRequestBodyLimit)).Decode(&req)
	if err != nil {
		sfe.log.Errf("failed to decode override request: %s", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.RateLimit == "" {
		http.Error(w, "rate limit not specified", http.StatusBadRequest)
		return
	}

	getValidated := func(name string) (string, error) {
		val := strings.TrimSpace(req.Fields[name])
		err := validateOverrideRequestField(name, val, req.RateLimit)
		if err != nil {
			return "", fmt.Errorf("invalid field %q: %w", name, err)
		}
		return val, nil
	}

	var baseFields = make(map[string]string)
	for _, name := range []string{
		// Note: not all of these fields will be included in the Zendesk ticket,
		// but they are all required for the submission to be considered valid.
		subscriberAgreementFieldName,
		privacyPolicyFieldName,
		mailingListFieldName,
		fundraisingFieldName,
		emailAddressFieldName,
		OrganizationFieldName,
		useCaseFieldName,
		TierFieldName,
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
		accountURI, err := getValidated(AccountURIFieldName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// TODO(#8360): Skip ticket creation and insert an override for
		// overrides matching the first N tiers of this limit.

		_, err = createNewOrdersPerAccountOverrideTicket(
			sfe.zendeskClient,
			baseFields[emailAddressFieldName],
			baseFields[useCaseFieldName],
			baseFields[OrganizationFieldName],
			baseFields[TierFieldName],
			accountURI,
		)
		if err != nil {
			sfe.log.Errf("failed to create override request ticket: %s", err)
			http.Error(w, "failed to create override request ticket", http.StatusInternalServerError)
			return
		}

	case rl.CertificatesPerDomainPerAccount.String():
		accountURI, err := getValidated(AccountURIFieldName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// TODO(#8360): Skip ticket creation and insert an override for
		// overrides matching the first N tiers of this limit.

		_, err = createCertificatesPerDomainPerAccountOverrideTicket(
			sfe.zendeskClient,
			baseFields[emailAddressFieldName],
			baseFields[useCaseFieldName],
			baseFields[OrganizationFieldName],
			baseFields[TierFieldName],
			accountURI,
		)
		if err != nil {
			sfe.log.Errf("failed to create override request ticket: %s", err)
			http.Error(w, "failed to create override request ticket", http.StatusInternalServerError)
			return
		}

	case rl.CertificatesPerDomain.String() + perDNSNameSuffix:
		registeredDomain, err := getValidated(RegisteredDomainFieldName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// TODO(#8360): Skip ticket creation and insert an override for
		// overrides matching the first N tiers of this limit.

		_, err = createCertificatesPerDomainOverrideTicket(
			sfe.zendeskClient,
			baseFields[emailAddressFieldName],
			baseFields[useCaseFieldName],
			baseFields[OrganizationFieldName],
			baseFields[TierFieldName],
			registeredDomain,
			"",
		)
		if err != nil {
			sfe.log.Errf("failed to create override request ticket: %s", err)
			http.Error(w, "failed to create override request ticket", http.StatusInternalServerError)
			return
		}

	case rl.CertificatesPerDomain.String() + perIPSuffix:
		ipAddress, err := getValidated(IPAddressFieldName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// TODO(#8360): Skip ticket creation and insert an override for
		// overrides matching the first N tiers of this limit.

		_, err = createCertificatesPerDomainOverrideTicket(
			sfe.zendeskClient,
			baseFields[emailAddressFieldName],
			baseFields[useCaseFieldName],
			baseFields[OrganizationFieldName],
			baseFields[TierFieldName],
			"",
			ipAddress,
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
