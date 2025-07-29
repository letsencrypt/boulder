package forms

import (
	"fmt"
	"html/template"
	"strings"
)

type Field interface {
	// RenderForm returns the HTML representation of the field.
	RenderField() template.HTML
}

type InputField struct {
	// displayName is the name displayed in the form UI.
	displayName string

	// name is the name of the field when submitted in the form. It is required
	// and must be unique within the form.
	name string

	// description is a short description displayed below the field. It is
	// required.
	description string

	// required indicates whether the field is required.
	required bool
}

func NewInputField(displayName, name, description string, required bool) *InputField {
	return &InputField{
		displayName: displayName,
		name:        name,
		description: description,
		required:    required,
	}
}

func (field InputField) RenderField() template.HTML {
	var reqAttr string
	if field.required {
		reqAttr = `required="required"`
	}
	return template.HTML(
		fmt.Sprintf(`
<div class="form-field">
	<label for="%[1]s">%[2]s</label><br>
	<small class="field-description">%[3]s</small><br>
	<input type="text" id="%[1]s" name="%[1]s" %[4]s>
	<div class="error-message"></div>
</div>`, field.name, field.displayName, field.description, reqAttr),
	)
}

type DropdownField struct {
	// displayName is the name displayed in the form UI.
	displayName string

	// name is the name of the field when submitted in the form. It is required
	// and must be unique within the form.
	name string

	// description is a short description displayed below the field. It is
	// required.
	description string

	// options is the list of options available in the dropdown.
	options []string

	// required indicates whether the field is required.
	required bool
}

func NewDropdownField(displayName, name, description string, options []string, required bool) Field {
	return &DropdownField{
		displayName: displayName,
		name:        name,
		description: description,
		options:     options,
		required:    required,
	}
}

func (field DropdownField) RenderField() template.HTML {
	var reqAttr string
	if field.required {
		reqAttr = `required="required"`
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf(`
<div class="form-field">
	<label for="%[1]s">%[2]s</label><br>
	<small class="field-description">%[3]s</small><br>
	<select id="%[1]s" name="%[1]s" %[4]s>
		<option value="" selected></option>`, field.name, field.displayName, field.description, reqAttr))
	for _, o := range field.options {
		b.WriteString(fmt.Sprintf(`<option value="%[1]s">%[1]s</option>`, o))
	}
	b.WriteString(`</select>
	<div class="error-message"></div>
</div>`)
	return template.HTML(b.String())
}

type TextareaField struct {
	// displayName is the name displayed in the form UI.
	displayName string

	// name is the name of the field when submitted in the form. It is required
	// and must be unique within the form.
	name string

	// description is a short description displayed below the field. It is
	// required.
	description string

	// rows is the number of lines to show in the textarea. Optional and
	// defaults to 4.
	rows int

	// required indicates whether the field is required.
	required bool
}

func NewTextareaField(displayName, name, description string, rows int, required bool) *TextareaField {
	return &TextareaField{
		displayName: displayName,
		name:        name,
		description: description,
		rows:        rows,
		required:    required,
	}
}

func (field TextareaField) RenderField() template.HTML {
	numRows := field.rows
	if numRows <= 0 {
		numRows = 4
	}
	var reqAttr string
	if field.required {
		reqAttr = `required="required"`
	}
	return template.HTML(fmt.Sprintf(`
<div class="form-field">
	<label for="%[1]s">%[2]s</label><br>
	<small class="field-description">%[3]s</small><br>
	<textarea id="%[1]s" name="%[1]s" rows="%[4]d" %[5]s></textarea>
	<div class="error-message"></div>
</div>`, field.name, field.displayName, field.description, numRows, reqAttr))
}

type CheckboxField struct {
	// displayName is the name displayed in the form UI.
	displayName string

	// name is the name of the field when submitted in the form. It is required
	// and must be unique within the form.
	name string

	// description is a short description displayed below the displayName.
	description string

	// text is the text displayed to the right of the checkbox. It is required.
	text string

	// required indicates whether the checkbox must be checked.
	required bool
}

func NewCheckboxField(displayName, name, description, text string, required bool) *CheckboxField {
	return &CheckboxField{
		displayName: displayName,
		name:        name,
		description: description,
		text:        text,
		required:    required,
	}
}

func (field CheckboxField) RenderField() template.HTML {
	var reqAttr string
	if field.required {
		reqAttr = `required="required"`
	}
	return template.HTML(fmt.Sprintf(`
<div class="highlight form-field checkbox-field" id="%[1]s-wrapper">
	<label for="%[1]s">%[2]s</label><br>
	<small class="field-description">%[3]s</small><br>
	<div class="checkbox-row">
		<input type="checkbox" id="%[1]s" name="%[1]s" %[5]s>
		<span class="checkbox-text">%[4]s</span>
	</div>
	<div class="error-message"></div>
</div>`, field.name, field.displayName, field.description, field.text, reqAttr))
}
