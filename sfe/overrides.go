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
	base = forms.NewBaseOverrideForm(
		forms.NewCheckboxField(
			"Privacy Policy Agreement (required)",
			rlo.PrivacyPolicyFieldName,
			`To use this form, you must agree to our <a href="https://letsencrypt.org/privacy">
privacy policy</a>.`,
			"I agree to the Let's Encrypt privacy policy.",
			true,
		),
		forms.NewDropdownField(
			"Contribute to Let’s Encrypt",
			rlo.FundraisingFieldName,
			`Is your organization interested in financially supporting Let's Encrypt?`,
			rlo.FundraisingOptions,
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
			`This helps us understand who is requesting the override 
and find the right contact person if needed.`,
			true,
		),
		forms.NewTextareaField(
			"Use Case",
			rlo.UseCaseFieldName,
			`Please describe the use case for this override request. 
This helps us understand the need for the override and how it will be used.`,
			4,
			true,
		),
	).RenderForm()

	newOrdersPerAccountForm = base + forms.NewNewOrdersPerAccountOverrideForm(
		forms.NewDropdownField(
			"Maximum Orders Per Week",
			rlo.TierFieldName,
			`The number of orders per week needed for this account. 
Please select the number that best matches your needs.`,
			rlo.NewOrdersPerAccountTiers,
			true,
		),
		forms.NewInputField(
			"Account URI",
			rlo.AccountURIFieldName,
			`The ACME account URI you're requesting the override for. 
For example: https://acme-v02.api.letsencrypt.org/acme/acct/12345.
Read more about Account IDs <a href="https://letsencrypt.org/docs/account-id">
here</a>.`,
			true,
		),
	).RenderForm()

	certificatesPerDomainForm = base + forms.NewCertificatesPerDomainOverrideForm(
		forms.NewDropdownField(
			"Maximum Certificates Per Week",
			rlo.TierFieldName,
			`The number of certificates per week needed for this domain 
and all subdomains. Please select the number that best matches your needs.`,
			rlo.CertificatesPerDomainTiers,
			true,
		),
		forms.NewInputField(
			"Registered Domain Name",
			rlo.RegisteredDomainFieldName,
			`The registered domain name you’re requesting the override 
for. This should be the base domain, for instance, example.com, not www.example.com 
or blog.example.com. For Internationalized Domain Names such as bücher.com, use the 
<a href="https://www.punycoder.com/">ASCII-compatible Punycode</a> form: xn--bcher-kva.com.`,
			true,
		),
	).RenderForm()

	certificatesPerDomainPerAccountForm = base + forms.NewCertificatesPerDomainPerAccountOverrideForm(
		forms.NewDropdownField(
			"Maximum Certificates Per Week",
			rlo.TierFieldName,
			`The number of certificates per week per registered 
domain name or IP address included in certificates requested by this account. 
Please select the number that best matches your needs.`,
			rlo.CertificatesPerDomainPerAccountTiers,
			true,
		),
		forms.NewInputField(
			"Account URI",
			rlo.AccountURIFieldName,
			`The account URI you're requesting the override 
for, for example: https://acme-v02.api.letsencrypt.org/acme/acct/12345.`,
			true,
		),
	).RenderForm()

	certificatesPerIPForm = base + forms.NewCertificatesPerIPOverrideForm(
		forms.NewDropdownField(
			"Maximum Certificates Per Week",
			rlo.TierFieldName,
			`The number of certificates per week needed for this IP  
address. Please select the number that best matches your needs.`,
			rlo.CertificatesPerDomainTiers,
			true,
		),
		forms.NewInputField(
			"IP Address",
			rlo.IPAddressFieldName,
			`The IPv4 or IPv6 address you’re requesting the override 
for. This should be the public IP address included in the certificate itself.`,
			true,
		),
	).RenderForm()
)

// NewOrdersPerAccountOverrideRequestHandler renders the Web UI for the
// NewOrdersPerAccount override request form.
func (sfe *SelfServiceFrontEndImpl) NewOrderPerAccountOverrideRequestHandler(w http.ResponseWriter, r *http.Request) {
	sfe.renderTemplate(w, "override.html", map[string]any{
		"FormHTML":  newOrdersPerAccountForm,
		"RateLimit": "NewOrdersPerAccount",
	})
}

// CertificatesPerDomainOverrideRequestHandler renders the Web UI for the
// CertificatesPerDomain override request form.
func (sfe *SelfServiceFrontEndImpl) CertificatesPerDomainOverrideRequestHandler(w http.ResponseWriter, r *http.Request) {
	sfe.renderTemplate(w, "override.html", map[string]any{
		"FormHTML":  certificatesPerDomainForm,
		"RateLimit": "CertificatesPerDomain",
	})
}

// CertificatesPerIPOverrideRequestHandler renders the Web UI for the
// CertificatesPerDomain override request form specific to IP addresses.
func (sfe *SelfServiceFrontEndImpl) CertificatesPerIPOverrideRequestHandler(w http.ResponseWriter, r *http.Request) {
	sfe.renderTemplate(w, "override.html", map[string]any{
		"FormHTML":  certificatesPerIPForm,
		"RateLimit": "CertificatesPerDomain",
	})
}

// CertificatesPerDomainPerAccountOverrideRequestHandler renders the Web UI for
// the CertificatesPerDomainPerAccount override request form.
func (sfe *SelfServiceFrontEndImpl) CertificatesPerDomainPerAccountOverrideRequestHandler(w http.ResponseWriter, r *http.Request) {
	sfe.renderTemplate(w, "override.html", map[string]any{
		"FormHTML":  certificatesPerDomainPerAccountForm,
		"RateLimit": "CertificatesPerDomainPerAccount",
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

func (sfe *SelfServiceFrontEndImpl) ValidateOverrideFieldHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req validationRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var valid bool
	var message string
	err = rlo.ValidateOverrideRequestField(req.Field, req.Value, req.RateLimit)
	if err != nil {
		message = err.Error()
	} else {
		valid = true
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(validationResponse{
		Field: req.Field,
		Valid: valid,
		Error: message,
	})
	if err != nil {
		http.Error(w, "failed to encode error response", http.StatusInternalServerError)
		return
	}
}

func (sfe *SelfServiceFrontEndImpl) OverrideSuccessHandler(w http.ResponseWriter, r *http.Request) {
	sfe.renderTemplate(w, "overrideSuccess.html", nil)
}

type overrideRequest struct {
	RateLimit string            `json:"rateLimit"`
	Fields    map[string]string `json:"fields"`
}

// SubmitOverrideRequestHandler handles the submission of override requests. It
// expects a POST request with a JSON payload (overrideRequest). It validates
// the form fields and processes the override request submission. If the request
// is successful, it redirects to a success page. If the request fails, it
// returns an error response.
func (sfe *SelfServiceFrontEndImpl) SubmitOverrideRequestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req overrideRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
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

	ticket := map[string]string{}

	for _, name := range []string{
		rlo.PrivacyPolicyFieldName,
		rlo.EmailAddressFieldName,
		rlo.OrganizationFieldName,
		rlo.UseCaseFieldName,
		rlo.FundraisingFieldName,
		rlo.TierFieldName,
	} {
		val, err := getValidated(name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ticket[name] = val
	}

	switch req.RateLimit {
	case rl.NewOrdersPerAccount.String():
		accountURI, err := getValidated(rlo.AccountURIFieldName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		_, err = rlo.CreateNewOrdersPerAccountOverrideTicket(
			sfe.zendeskClient,
			ticket[rlo.EmailAddressFieldName],
			ticket[rlo.UseCaseFieldName],
			ticket[rlo.FundraisingFieldName],
			ticket[rlo.OrganizationFieldName],
			ticket[rlo.TierFieldName],
			accountURI,
		)
		if err != nil {
			http.Error(w, "failed to create ticket", http.StatusInternalServerError)
			return
		}

	case rl.CertificatesPerDomain.String():
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

		if regDomain != "" {
			_, err = getValidated(rlo.RegisteredDomainFieldName)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		} else {
			_, err = getValidated(rlo.IPAddressFieldName)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}

		_, err = rlo.CreateCertificatesPerDomainOverrideTicket(
			sfe.zendeskClient,
			ticket[rlo.EmailAddressFieldName],
			ticket[rlo.UseCaseFieldName],
			ticket[rlo.FundraisingFieldName],
			ticket[rlo.OrganizationFieldName],
			ticket[rlo.TierFieldName],
			regDomain,
			ip,
		)
		if err != nil {
			http.Error(w, "failed to create ticket", http.StatusInternalServerError)
			return
		}

	case rl.CertificatesPerDomainPerAccount.String():
		accountURI, err := getValidated(rlo.AccountURIFieldName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		_, err = rlo.CreateCertificatesPerDomainPerAccountOverrideTicket(
			sfe.zendeskClient,
			ticket[rlo.EmailAddressFieldName],
			ticket[rlo.UseCaseFieldName],
			ticket[rlo.FundraisingFieldName],
			ticket[rlo.OrganizationFieldName],
			ticket[rlo.TierFieldName],
			accountURI,
		)
		if err != nil {
			http.Error(w, "failed to create ticket", http.StatusInternalServerError)
			return
		}

	default:
		http.Error(w, "unknown rate limit", http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, "/override/success", http.StatusSeeOther)
}
