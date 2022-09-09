package probers

import (
	"reflect"
	"testing"

	"github.com/letsencrypt/boulder/observer/probers"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v3"
)

func TestCRLConf_MakeProber(t *testing.T) {
	conf := CRLConf{}
	colls := conf.Instrument()
	badColl := prometheus.Collector(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "obs_crl_foo",
			Help: "Hmmm, this shouldn't be here...",
		},
		[]string{},
	))
	type fields struct {
		URL string
	}
	tests := []struct {
		name    string
		fields  fields
		colls   map[string]prometheus.Collector
		wantErr bool
	}{
		// valid
		{"valid fqdn", fields{"http://example.com"}, colls, false},
		{"valid fqdn with path", fields{"http://example.com/foo/bar"}, colls, false},
		{"valid hostname", fields{"http://example"}, colls, false},
		// invalid
		{"bad fqdn", fields{":::::"}, colls, true},
		{"missing scheme", fields{"example.com"}, colls, true},
		{
			"unexpected collector",
			fields{"http://example.com"},
			map[string]prometheus.Collector{"obs_crl_foo": badColl},
			true,
		},
		{
			"missing collectors",
			fields{"http://example.com"},
			map[string]prometheus.Collector{},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := CRLConf{
				URL: tt.fields.URL,
			}
			p, err := c.MakeProber(tt.colls)
			if err == nil {
				if tt.wantErr {
					t.Errorf("CRLConf.MakeProber() error = %v, wantErr %v", err, tt.wantErr)
				} else {
					prober := p.(CRLProbe)
					if prober.cThisUpdate == nil {
						t.Errorf("CRLConf.MakeProber() returned CRLProbe with nil cThisUpdate")
					}
					if prober.cNextUpdate == nil {
						t.Errorf("CRLConf.MakeProber() returned CRLProbe with nil cNextUpdate")
					}
					if prober.cCertCount == nil {
						t.Errorf("CRLConf.MakeProber() returned CRLProbe with nil cCertCount")
					}
				}
			} else if err != nil && !tt.wantErr {
				t.Errorf("CRLConf.MakeProber() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
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
