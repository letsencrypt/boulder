package forms

import (
	"html/template"
)

// Form is an interface for a collection of fields that can be rendered as an
// HTML template.
type Form interface {
	RenderForm() template.HTML
}

type baseOverrideForm struct {
	subscriberAgreement Field
	privacyPolicy       Field
	requesterEmail      Field
	organization        Field
	useCase             Field
	mailingList         Field
}

var _ Form = (*baseOverrideForm)(nil)

// NewBaseOverrideForm creates a new base override request form.
func NewBaseOverrideForm(subscriberAgreement, privacyPolicy, mailingList, requesterEmail, organization, useCase Field) Form {
	return &baseOverrideForm{
		subscriberAgreement: subscriberAgreement,
		privacyPolicy:       privacyPolicy,
		mailingList:         mailingList,
		requesterEmail:      requesterEmail,
		organization:        organization,
		useCase:             useCase,
	}
}

// RenderForm renders the fields of the base override request form as an HTML
// template. It is required to satisfy the Form interface.
func (form baseOverrideForm) RenderForm() template.HTML {
	return form.subscriberAgreement.RenderField() +
		form.privacyPolicy.RenderField() +
		form.mailingList.RenderField() +
		form.requesterEmail.RenderField() +
		form.organization.RenderField() +
		form.useCase.RenderField()
}

type newOrdersPerAccountOverrideForm struct {
	tier       Field
	accountURI Field
}

var _ Form = (*newOrdersPerAccountOverrideForm)(nil)

// NewNewOrdersPerAccountOverrideForm creates a new override request form for
// the NewOrdersPerAccount rate limit.
func NewNewOrdersPerAccountOverrideForm(tier, accountURI Field) Form {
	return &newOrdersPerAccountOverrideForm{
		tier:       tier,
		accountURI: accountURI,
	}
}

// RenderForm renders the fields of the NewOrdersPerAccount override request
// form as an HTML template. It is required to satisfy the Form interface.
func (form newOrdersPerAccountOverrideForm) RenderForm() template.HTML {
	return form.tier.RenderField() + form.accountURI.RenderField()
}

type certificatesPerDomainOverrideForm struct {
	tier             Field
	registeredDomain Field
}

var _ Form = (*certificatesPerDomainOverrideForm)(nil)

// NewCertificatesPerDomainOverrideForm creates a new override request form for
// the CertificatesPerDomain rate limit.
func NewCertificatesPerDomainOverrideForm(tier, registeredDomain Field) Form {
	return &certificatesPerDomainOverrideForm{
		tier:             tier,
		registeredDomain: registeredDomain,
	}
}

// RenderForm renders the fields of the CertificatesPerDomain override request
// form as an HTML template. It is required to satisfy the Form interface.
func (form certificatesPerDomainOverrideForm) RenderForm() template.HTML {
	return form.tier.RenderField() + form.registeredDomain.RenderField()
}

type certificatesPerIPOverrideForm struct {
	tier      Field
	ipAddress Field
}

var _ Form = (*certificatesPerIPOverrideForm)(nil)

// NewCertificatesPerIPOverrideForm creates a new override request form for the
// CertificatesPerDomain rate limit.
func NewCertificatesPerIPOverrideForm(tier, ipAddress Field) Form {
	return &certificatesPerIPOverrideForm{
		tier:      tier,
		ipAddress: ipAddress,
	}
}

// RenderForm renders the fields of the CertificatesPerIP override request form
// as an HTML template. It is required to satisfy the Form interface.
func (form certificatesPerIPOverrideForm) RenderForm() template.HTML {
	return form.tier.RenderField() + form.ipAddress.RenderField()
}

type certificatesPerDomainPerAccountOverrideForm struct {
	tier       Field
	accountURI Field
}

var _ Form = (*certificatesPerDomainPerAccountOverrideForm)(nil)

// NewCertificatesPerDomainPerAccountOverrideForm creates a new override request
// form for the CertificatesPerDomainPerAccount rate limit.
func NewCertificatesPerDomainPerAccountOverrideForm(tier, accountURI Field) Form {
	return &certificatesPerDomainPerAccountOverrideForm{
		tier:       tier,
		accountURI: accountURI,
	}
}

// RenderForm renders the fields of the CertificatesPerDomainPerAccount override
// request form as an HTML template. It is required to satisfy the Form
// interface.
func (form certificatesPerDomainPerAccountOverrideForm) RenderForm() template.HTML {
	return form.tier.RenderField() + form.accountURI.RenderField()
}
