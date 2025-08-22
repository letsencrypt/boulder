package forms

import (
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestInputFieldRenderField(t *testing.T) {
	cases := []struct {
		name     string
		required bool
	}{
		{"required", true},
		{"optional", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := NewInputField("Email Address", "email", "Where we can reach you", tc.required)
			html := string(f.RenderField())

			test.AssertContains(t, html, `<div class="form-field">`)
			test.AssertContains(t, html, `<label for="email">Email Address</label>`)
			test.AssertContains(t, html, `<small class="field-description">Where we can reach you</small>`)
			test.AssertContains(t, html, `<input type="text" id="email" name="email"`)

			if tc.required {
				test.AssertContains(t, html, `required="required"`)
				return
			}
			test.AssertNotContains(t, html, `required="required"`)
		})
	}
}

func TestDropdownFieldRenderField(t *testing.T) {
	cases := []struct {
		name     string
		required bool
	}{
		{"required", true},
		{"optional", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := []string{"Small", "Medium", "Large"}
			f := NewDropdownField("Size", "size", "Pick one", opts, tc.required)

			html := string(f.RenderField())

			test.AssertContains(t, html, `<div class="form-field">`)
			test.AssertContains(t, html, `<label for="size">Size</label>`)
			test.AssertContains(t, html, `<small class="field-description">Pick one</small>`)
			test.AssertContains(t, html, `<select id="size" name="size"`)
			test.AssertContains(t, html, `<option value="" selected></option>`)
			test.AssertContains(t, html, `<option value="Small">Small</option>`)
			test.AssertContains(t, html, `<option value="Medium">Medium</option>`)
			test.AssertContains(t, html, `<option value="Large">Large</option>`)

			if tc.required {
				test.AssertContains(t, html, `required="required"`)
				return
			}
			test.AssertNotContains(t, html, `required="required"`)
		})
	}
}

func TestTextareaFieldRenderField(t *testing.T) {
	cases := []struct {
		name     string
		rows     int
		required bool
		wantRows string
	}{
		{"explicit rows", 7, true, `rows="7"`},
		{"default rows when zero", 0, false, `rows="4"`},
		{"default rows when negative", -3, true, `rows="4"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := NewTextareaField("Use Case", "useCase", "Tell us more", tc.rows, tc.required)
			html := string(f.RenderField())

			test.AssertContains(t, html, `<div class="form-field">`)
			test.AssertContains(t, html, `<label for="useCase">Use Case</label>`)
			test.AssertContains(t, html, `<small class="field-description">Tell us more</small>`)
			test.AssertContains(t, html, `<textarea id="useCase" name="useCase"`)
			test.AssertContains(t, html, tc.wantRows)

			if tc.required {
				test.AssertContains(t, html, `required="required"`)
				return
			}
			test.AssertNotContains(t, html, `required="required"`)
		})
	}
}

func TestCheckboxFieldRenderField(t *testing.T) {
	cases := []struct {
		name     string
		required bool
	}{
		{"required", true},
		{"optional", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := NewCheckboxField("Subscriber Agreement", "sa", "I agree to the terms", tc.required)
			html := string(f.RenderField())

			test.AssertContains(t, html, `<div class="highlight form-field checkbox-field" id="sa-wrapper">`)
			test.AssertContains(t, html, `<label for="sa">Subscriber Agreement</label>`)
			test.AssertContains(t, html, `<div class="checkbox-row">`)
			test.AssertContains(t, html, `<input type="checkbox" id="sa" name="sa"`)
			test.AssertContains(t, html, `<span class="checkbox-text">I agree to the terms</span>`)

			if tc.required {
				test.AssertContains(t, html, `required="required"`)
				return
			}
			test.AssertNotContains(t, html, `required="required"`)
		})
	}
}
