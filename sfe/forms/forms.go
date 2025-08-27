package forms

import (
	"html/template"
)

type Form []Field

func NewForm(fields ...Field) *Form {
	f := Form(fields)
	return &f
}

func (form *Form) RenderForm() template.HTML {
	var res template.HTML
	for _, field := range *form {
		res += field.RenderField()
	}
	return res
}
