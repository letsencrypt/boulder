package forms

import (
	"html/template"
)

type Form interface {
	RenderForm() template.HTML
}

type BaseOverrideForm struct {
	privacyPolicy  Field
	fundraising    Field
	requesterEmail Field
	organization   Field
	useCase        Field
}

func NewBaseOverrideForm(privacyPolicy, fundraising, requesterEmail, organization, useCase Field) Form {
	return &BaseOverrideForm{
		privacyPolicy:  privacyPolicy,
		fundraising:    fundraising,
		requesterEmail: requesterEmail,
		organization:   organization,
		useCase:        useCase,
	}
}

func (form BaseOverrideForm) RenderForm() template.HTML {
	return form.privacyPolicy.RenderField() +
		form.fundraising.RenderField() +
		form.requesterEmail.RenderField() +
		form.organization.RenderField() +
		form.useCase.RenderField()
}

type NewOrdersPerAccountOverrideForm struct {
	tier       Field
	accountURI Field
}

func NewNewOrdersPerAccountOverrideForm(tier Field, accountURI Field) Form {
	return &NewOrdersPerAccountOverrideForm{
		tier:       tier,
		accountURI: accountURI,
	}
}

func (form NewOrdersPerAccountOverrideForm) RenderForm() template.HTML {
	return form.tier.RenderField() + form.accountURI.RenderField()
}

type CertificatesPerDomainOverrideForm struct {
	tier             Field
	registeredDomain Field
}

func NewCertificatesPerDomainOverrideForm(tier Field, registeredDomain Field) Form {
	return &CertificatesPerDomainOverrideForm{
		tier:             tier,
		registeredDomain: registeredDomain,
	}
}

func (form CertificatesPerDomainOverrideForm) RenderForm() template.HTML {
	return form.tier.RenderField() + form.registeredDomain.RenderField()
}

type CertificatesPerIPOverrideForm struct {
	tier      Field
	ipAddress Field
}

func NewCertificatesPerIPOverrideForm(tier Field, ipAddress Field) Form {
	return &CertificatesPerIPOverrideForm{
		tier:      tier,
		ipAddress: ipAddress,
	}
}

func (form CertificatesPerIPOverrideForm) RenderForm() template.HTML {
	return form.tier.RenderField() + form.ipAddress.RenderField()
}

type CertificatesPerDomainPerAccountOverrideForm struct {
	tier       Field
	accountURI Field
}

func NewCertificatesPerDomainPerAccountOverrideForm(tier Field, accountURI Field) Form {
	return &CertificatesPerDomainPerAccountOverrideForm{
		tier:       tier,
		accountURI: accountURI,
	}
}

func (form CertificatesPerDomainPerAccountOverrideForm) RenderForm() template.HTML {
	return form.tier.RenderField() + form.accountURI.RenderField()
}
