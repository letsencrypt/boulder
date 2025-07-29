package sfe

import (
	"encoding/json"
	"net/http"

	rlo "github.com/letsencrypt/boulder/ratelimits/overriderequests"
	"github.com/letsencrypt/boulder/sfe/forms"
)

var (
	privacyPolicy = forms.NewCheckboxField(
		"Privacy Policy Agreement (required)",
		rlo.PrivacyPolicyFieldName,
		`To use this form, you must agree to our 
<a href="https://letsencrypt.org/privacy">privacy policy</a>.`,
		"I agree to the Let's Encrypt privacy policy.",
		true,
	)

	fundraising = forms.NewDropdownField(
		"Contribute to Let’s Encrypt",
		rlo.FundraisingFieldName,
		`Is your organization interested in financially supporting Let's Encrypt?`,
		rlo.FundraisingOptions,
		true,
	)

	emailAddress = forms.NewInputField(
		"Email Address",
		rlo.EmailAddressFieldName,
		`An email address where we can reach you regarding this
request.`,
		true,
	)

	organization = forms.NewInputField(
		"Organization or Project",
		rlo.OrganizationFieldName,
		`This helps us understand who is requesting the override 
and find the right contact person if needed.`,
		true,
	)

	useCase = forms.NewTextareaField(
		"Use Case",
		rlo.UseCase,
		`Please describe the use case for this override request.
This helps us understand the need for the override and how it will be used.`,
		4,
		true,
	)
)
var base = forms.NewBaseOverrideForm(privacyPolicy, fundraising, emailAddress, organization, useCase)

var newOrdersPerAccountOverrideForm = forms.NewNewOrdersPerAccountOverrideForm(
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
For example: https://acme-v02.api.letsencrypt.org/acme/acct/12345.`,
		true,
	),
)

func (sfe *SelfServiceFrontEndImpl) NewOrderPerAccountOverrideRequestHandler(w http.ResponseWriter, r *http.Request) {
	sfe.renderTemplate(w, "override.html", map[string]any{
		"FormHTML":  base.RenderForm() + newOrdersPerAccountOverrideForm.RenderForm(),
		"RateLimit": "NewOrdersPerAccount",
	})
}

var certificatesPerDomainOverrideForm = forms.NewCertificatesPerDomainOverrideForm(
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
)

func (sfe *SelfServiceFrontEndImpl) CertificatesPerDomainOverrideRequestHandler(w http.ResponseWriter, r *http.Request) {
	sfe.renderTemplate(w, "override.html", map[string]any{
		"FormHTML":  base.RenderForm() + certificatesPerDomainOverrideForm.RenderForm(),
		"RateLimit": "CertificatesPerDomain",
	})
}

var certificatesPerIPOverrideForm = forms.NewCertificatesPerIPOverrideForm(
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
)

func (sfe *SelfServiceFrontEndImpl) CertificatesPerIPOverrideRequestHandler(w http.ResponseWriter, r *http.Request) {
	sfe.renderTemplate(w, "override.html", map[string]any{
		"FormHTML":  base.RenderForm() + certificatesPerIPOverrideForm.RenderForm(),
		"RateLimit": "CertificatesPerDomain",
	})
}

var certificatesPerDomainPerAccountOverrideForm = forms.NewCertificatesPerDomainPerAccountOverrideForm(
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
)

func (sfe *SelfServiceFrontEndImpl) CertificatesPerDomainPerAccountOverrideRequestHandler(w http.ResponseWriter, r *http.Request) {
	sfe.renderTemplate(w, "override.html", map[string]any{
		"FormHTML":  base.RenderForm() + certificatesPerDomainPerAccountOverrideForm.RenderForm(),
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
	valid, message := rlo.ValidateOverrideRequestField(req.Field, req.Value, req.RateLimit)

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

type overrideRequest struct {
	RateLimit string            `json:"rateLimit"`
	Fields    map[string]string `json:"fields"`
}

// SubmitOverrideRequestHandler handles the submission of override requests.
// It expects a POST request with a JSON payload containing the rate limit name
// and form fields. It validates the form fields and processes the override
// request submission. If the request is successful, it redirects to a success
// page. If the request fails, it returns an error response.
func (sfe *SelfServiceFrontEndImpl) SubmitOverrideRequestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rateLimit := r.FormValue("rateLimit")
	if rateLimit == "" {
		http.Error(w, "rate limit not specified", http.StatusBadRequest)
		return
	}

	var req overrideRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	for field, value := range req.Fields {
		valid, message := rlo.ValidateOverrideRequestField(field, value, rateLimit)
		if !valid {
			http.Error(w, message, http.StatusBadRequest)
			return
		}
	}
	http.Redirect(w, r, "/override/success", http.StatusSeeOther)
}

func (sfe *SelfServiceFrontEndImpl) OverrideSuccessHandler(w http.ResponseWriter, r *http.Request) {
	sfe.renderTemplate(w, "overrideSuccess.html", nil)
}
