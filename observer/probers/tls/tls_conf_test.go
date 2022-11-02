package probers

import (
	"reflect"
	"testing"

	"github.com/letsencrypt/boulder/observer/probers"
	"gopkg.in/yaml.v3"
)

func TestTLSConf_MakeProber(t *testing.T) {
	type fields struct {
		URL		string
		Root	string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		// valid
		{"valid fqdn", fields{"http://example.com", "ISRG Root X1"}, false},
		{"valid fqdn with path", fields{"http://example.com/foo/bar", "ISRG Root X1"}, false},
		{"valid hostname", fields{"http://example", "ISRG Root X1"}, false},
		// invalid
		{"bad fqdn", fields{":::::", "ISRG Root X1"}, true},
		{"missing scheme", fields{"example.com", "ISRG Root X1"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := TLSConf{
				URL:    tt.fields.URL,
			}
			if _, err := c.MakeProber(nil); (err != nil) != tt.wantErr {
				t.Errorf("TLSConf.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTLSConf_UnmarshalSettings(t *testing.T) {
	type fields struct {
		url       interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		want    probers.Configurer
		wantErr bool
	}{
		{"valid", fields{"google.com"}, TLSConf{"google.com", "ISRG Root X1"}, false},
		{"invalid (map)", fields{make(map[string]interface{})}, nil, true},
		{"invalid (list)", fields{make([]string, 0)}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := probers.Settings{
				"url":       tt.fields.url,
			}
			settingsBytes, _ := yaml.Marshal(settings)
			c := TLSConf{}
			got, err := c.UnmarshalSettings(settingsBytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("DNSConf.UnmarshalSettings() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DNSConf.UnmarshalSettings() = %v, want %v", got, tt.want)
			}
		})
	}
}
