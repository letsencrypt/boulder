package probers

import (
	"reflect"
	"testing"

	"github.com/letsencrypt/boulder/observer/probers"
	"gopkg.in/yaml.v3"
)

func TestTLSConf_MakeProber(t *testing.T) {
	goodURL, goodRoot := "http://example.com", "/O=Internet Security Research Group/CN=ISRG Root X1"
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
		{"valid fqdn", fields{"http://example.com", goodRoot}, false},
		{"valid fqdn with path", fields{"http://example.com/foo/bar", goodRoot}, false},
		{"valid hostname", fields{"http://example", goodRoot}, false},
		// invalid
		{"bad fqdn", fields{":::::", goodRoot}, true},
		{"missing scheme", fields{"example.com", goodRoot}, true},
		{"empty root", fields{goodURL, ""}, true},
		{"missing root org", fields{goodURL, "/CN=ISRG Root X1"}, true},
		{"wrong root format", fields{goodURL, "Internet Security Research Group, ISRG Root X1"}, true},
		{"country in root", fields{goodURL, "/C:US/O=Internet Security Research Group/CN=ISRG Root X1"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := TLSConf{
				URL:    tt.fields.URL,
				Root:	tt.fields.Root,
			}
			if _, err := c.MakeProber(nil); (err != nil) != tt.wantErr {
				t.Errorf("TLSConf.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTLSConf_UnmarshalSettings(t *testing.T) {
	type fields struct {
		url		interface{}
		root	interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		want    probers.Configurer
		wantErr bool
	}{
		{"valid", fields{"google.com", "/O=Internet Security Research Group/CN=ISRG Root X1"}, TLSConf{"google.com", "/O=Internet Security Research Group/CN=ISRG Root X1", "valid"}, false},
		{"invalid", fields{42, 42}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := probers.Settings{
				"url":		tt.fields.url,
				"root":		tt.fields.root,
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
