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
			if _, err := c.MakeProber(tt.colls); (err != nil) != tt.wantErr {
				t.Errorf("CRLConf.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCRLConf_Instrument(t *testing.T) {
	t.Run("instrument", func(t *testing.T) {
		conf := CRLConf{}
		colls := conf.Instrument()
		if colls == nil {
			t.Errorf("crl prober defines metrics but received nil collector map")
			return
		}
		var nu, tu, rcc *prometheus.GaugeVec
		for name, coll := range colls {
			switch name {
			case nextUpdateName:
				_, ok := coll.(*prometheus.GaugeVec)
				if !ok {
					t.Errorf("CRLConf.Instrument() returned collector '%s' of wrong type, got: %T, expected *prometheus.GaugeVec", name, nu)
					return
				}
				nu = coll.(*prometheus.GaugeVec)
			case thisUpdateName:
				_, ok := coll.(*prometheus.GaugeVec)
				if !ok {
					t.Errorf("CRLConf.Instrument() returned collector '%s' of wrong type, got: %T, expected *prometheus.GaugeVec", name, tu)
					return
				}
				tu = coll.(*prometheus.GaugeVec)
			case certCountName:
				_, ok := coll.(*prometheus.GaugeVec)
				if !ok {
					t.Errorf("CRLConf.Instrument() returned collector '%s' of wrong type, got: %T, expected *prometheus.GaugeVec", name, rcc)
					return
				}
				rcc = coll.(*prometheus.GaugeVec)
			default:
				t.Errorf("CRLConf.Instrument() returned unexpected collector '%s'", name)
				return
			}
		}
		if nu == nil {
			t.Errorf("CRLConf.Instrument() did not return collector '%s'", nextUpdateName)
			return
		}
		if tu == nil {
			t.Errorf("CRLConf.Instrument() did not return collector '%s'", thisUpdateName)
			return
		}
		if rcc == nil {
			t.Errorf("CRLConf.Instrument() did not return collector '%s'", certCountName)
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
