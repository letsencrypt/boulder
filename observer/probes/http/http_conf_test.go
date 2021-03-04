package observer

import "testing"

func TestHTTPConf_Validate(t *testing.T) {
	type fields struct {
		URL   string
		RCode int
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		// valid
		{"valid fqdn valid rcode", fields{"http://example.com", 200}, false},
		{"valid hostname valid rcode", fields{"example", 200}, true},
		// invalid
		{"valid fqdn bad rcode", fields{"http://example.com", 0}, true},
		{"bad fqdn good rcode", fields{":::::", 200}, true},
		{"missing scheme", fields{"example.com", 200}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := HTTPConf{
				URL:   tt.fields.URL,
				RCode: tt.fields.RCode,
			}
			if err := c.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("HTTPConf.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
