package probers

import (
	"reflect"
	"testing"

	"github.com/letsencrypt/boulder/observer/probers"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v3"
)

func TestTLSConf_MakeProber(t *testing.T) {
	goodURL, goodRoot, goodResponse := "http://example.com", "/O=Internet Security Research Group/CN=ISRG Root X1", "valid"
	colls := TLSConf{}.Instrument()
	badColl := prometheus.Collector(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "obs_crl_foo",
			Help: "Hmmm, this shouldn't be here...",
		},
		[]string{},
	))
	type fields struct {
		URL			string
		Root		string
		Response	string
	}
	tests := []struct {
		name    string
		fields  fields
		colls	map[string]prometheus.Collector
		wantErr bool
	}{
		// valid
		{"valid fqdn", fields{"http://example.com", "/O:/CN:", "valid"}, colls, false},
		{"valid fqdn with path", fields{"http://example.com/foo/bar", "/O:ISRG/CN:Root X3", "Revoked"}, colls, false},
		{"valid hostname", fields{"http://example", "/O:IdenTrust/CN:Root E1", "EXPIRED"}, colls, false},
		
		// invalid url
		{"bad fqdn", fields{":::::", goodRoot, goodResponse}, colls, true},
		{"missing scheme", fields{"example.com", goodRoot, goodResponse}, colls, true},
		
		// invalid root
		{"empty root", fields{goodURL, "", goodResponse}, colls, true},
		{"missing root org", fields{goodURL, "/CN=ISRG Root X1", goodResponse}, colls, true},
		{"wrong root format", fields{goodURL, "Internet Security Research Group, ISRG Root X1", goodResponse}, colls, true},
		{"country in root", fields{goodURL, "/C:US/O=Internet Security Research Group/CN=ISRG Root X1", goodResponse}, colls,  true},
		{"no extra spaces in root", fields{goodURL, "O=Internet Security Research Group /CN=ISRG Root X1", goodResponse}, colls, true},
		
		// invalid response
		{"empty response", fields{goodURL, goodRoot, ""}, colls, true},
		{"unaccepted response", fields{goodURL, goodRoot, "invalid"}, colls, true},

		//invalid collector
		{
			"unexpected collector",
			fields{"http://example.com", goodRoot, goodResponse},
			map[string]prometheus.Collector{"obs_crl_foo": badColl},
			true,
		},
		{
			"missing collectors",
			fields{"http://example.com", goodRoot, goodResponse},
			map[string]prometheus.Collector{},
			true,
		},
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
