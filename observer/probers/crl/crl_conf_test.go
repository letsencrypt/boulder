package probers

import (
	"reflect"
	"testing"

	"github.com/letsencrypt/boulder/observer/probers"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v3"
)

func TestCRLConf_MakeProber(t *testing.T) {
	type fields struct {
		URL string
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
			c := CRLConf{
				URL: tt.fields.URL,
			}
			if _, err := c.MakeProber(); (err != nil) != tt.wantErr {
				t.Errorf("CRLConf.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCRLConf_AddCollectors(t *testing.T) {
	t.Run("collectors get added", func(t *testing.T) {
		c := CRLConf{"http://example.com"}
		// Make sure ProberCollectors is initialized but empty
		probers.ProberCollectors = make(map[string]prometheus.Collector)
		c.AddCollectors()
		_, ok := probers.ProberCollectors["obs_crl_next_update"]
		if !ok {
			t.Errorf("CRLConf.Validate() collector '%s' wasn't added", "obs_crl_next_update")
		}
		_, ok = probers.ProberCollectors["obs_crl_this_update"]
		if !ok {
			t.Errorf("CRLConf.Validate() collector '%s' wasn't added", "obs_crl_this_update")
		}
		_, ok = probers.ProberCollectors["obs_crl_revoked_cert_count"]
		if !ok {
			t.Errorf("CRLConf.Validate() collector '%s' wasn't added", "obs_crl_revoked_cert_count")
		}
	})
}

func TestCRLConf_UnmarshalSettings(t *testing.T) {
	type fields struct {
		url interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		want    probers.Configurer
		wantErr bool
	}{
		{"valid", fields{"google.com"}, CRLConf{"google.com"}, false},
		{"invalid (map)", fields{make(map[string]interface{})}, nil, true},
		{"invalid (list)", fields{make([]string, 0)}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := probers.Settings{
				"url": tt.fields.url,
			}
			settingsBytes, _ := yaml.Marshal(settings)
			t.Log(string(settingsBytes))
			c := CRLConf{}
			got, err := c.UnmarshalSettings(settingsBytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("CRLConf.UnmarshalSettings() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CRLConf.UnmarshalSettings() = %v, want %v", got, tt.want)
			}
		})
	}
}
