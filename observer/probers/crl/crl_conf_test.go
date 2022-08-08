package probers

import (
	"reflect"
	"testing"

	"github.com/letsencrypt/boulder/observer/probers"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v3"
)

func TestCRLConfigurer_MakeProber(t *testing.T) {
	type fields struct {
		URL    string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		// valid
		{"valid fqdn", fields{"http://example.com"}, false},
		{"valid hostname", fields{"example"}, true},
		// invalid
		{"bad fqdn", fields{":::::"}, true},
		{"missing scheme", fields{"example.com"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := CRLConfigurer{
				URL:    tt.fields.URL,
			}
			if _, err := c.MakeProber(); (err != nil) != tt.wantErr {
				t.Errorf("CRLConfigurer.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCRLConfigurer_AddCollectors(t *testing.T) {
	t.Run("collectors get added", func(t *testing.T) {
		c := CRLConfigurer{"http://example.com"}
		// Make sure ProberCollectors is initialized but empty
		probers.ProberCollectors = make(map[string]prometheus.Collector)
		c.AddCollectors()
		_, ok := probers.ProberCollectors["obs_crl_next_update"]
		if !ok {
			t.Errorf("CRLConfigurer.Validate() collector '%s' wasn't added", "obs_crl_next_update")
		}
		_, ok = probers.ProberCollectors["obs_crl_this_update"]
		if !ok {
			t.Errorf("CRLConfigurer.Validate() collector '%s' wasn't added", "obs_crl_this_update")
		}
		_, ok = probers.ProberCollectors["obs_crl_revoked_cert_count"]
		if !ok {
			t.Errorf("CRLConfigurer.Validate() collector '%s' wasn't added", "obs_crl_revoked_cert_count")
		}
	})
}

func TestCRLConfigurer_UnmarshalSettings(t *testing.T) {
	type fields struct {
		url       interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		want    probers.Configurer
		wantErr bool
	}{
		{"valid", fields{"google.com"}, CRLConfigurer{"google.com"}, false},
		{"invalid (map)", fields{make(map[string]interface{})}, nil, true},
		{"invalid (list)", fields{make([]string, 0)}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := probers.Settings{
				"url":       tt.fields.url,
			}
			settingsBytes, _ := yaml.Marshal(settings)
			t.Log(string(settingsBytes))
			c := CRLConfigurer{}
			got, err := c.UnmarshalSettings(settingsBytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("CRLConfigurer.UnmarshalSettings() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CRLConfigurer.UnmarshalSettings() = %v, want %v", got, tt.want)
			}
		})
	}
}
