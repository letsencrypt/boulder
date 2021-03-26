package probers

import (
	"reflect"
	"testing"

	"github.com/letsencrypt/boulder/observer/probers"
	"gopkg.in/yaml.v2"
)

func TestHTTPConf_MakeProber(t *testing.T) {
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
		{"valid fqdn no rcode", fields{"http://example.com", nil}, true},
		{"valid fqdn invalid rcode", fields{"http://example.com", []int{1000}}, true},
		{"valid fqdn 1 invalid rcode", fields{"http://example.com", []int{200, 1000}}, true},
		{"bad fqdn good rcode", fields{":::::", []int{200}}, true},
		{"missing scheme", fields{"example.com", []int{200}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := HTTPConf{
				URL:    tt.fields.URL,
				RCodes: tt.fields.RCodes,
			}
			if _, err := c.MakeProber(); (err != nil) != tt.wantErr {
				t.Errorf("HTTPConf.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHTTPConf_UnmarshalSettings(t *testing.T) {
	type fields struct {
		url    interface{}
		rcodes interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		want    probers.Configurer
		wantErr bool
	}{
		{"valid", fields{"google.com", []int{200}}, HTTPConf{"google.com", []int{200}}, false},
		{"invalid", fields{42, 42}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := probers.Settings{
				"url":    tt.fields.url,
				"rcodes": tt.fields.rcodes,
			}
			settingsBytes, _ := yaml.Marshal(settings)
			c := HTTPConf{}
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
