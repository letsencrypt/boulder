package observer

import "testing"

func TestHTTPConf_Validate(t *testing.T) {
	type fields struct {
		URL    string
		RCodes []int
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		// valid
		{"valid fqdn valid rcode", fields{"http://example.com", []int{200}}, false},
		{"valid hostname valid rcode", fields{"example", []int{200}}, true},
		// invalid
		{"valid fqdn bad rcode", fields{"http://example.com", nil}, true},
		{"bad fqdn good rcode", fields{":::::", []int{200}}, true},
		{"missing scheme", fields{"example.com", []int{200}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := HTTPConf{
				URL:    tt.fields.URL,
				RCodes: tt.fields.RCodes,
			}
			if err := c.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("HTTPConf.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
