package observer

import (
	"testing"
)

func TestDNSConf_validateServer(t *testing.T) {
	type fields struct {
		Server string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		// ipv4 cases
		{"ipv4 with port", fields{"1.1.1.1:53"}, false},
		{"ipv4 without port", fields{"1.1.1.1"}, true},
		{"ipv4 port num missing", fields{"1.1.1.1:"}, true},
		{"ipv4 string for port", fields{"1.1.1.1:foo"}, true},
		{"ipv4 port out of range high", fields{"1.1.1.1:65536"}, true},
		{"ipv4 port out of range low", fields{"1.1.1.1:0"}, true},

		// ipv6 cases
		{"ipv6 with port", fields{"2606:4700:4700::1111:53"}, false},
		{"ipv6 without port", fields{"2606:4700:4700::1111"}, true},
		{"ipv6 port num missing", fields{"2606:4700:4700::1111:"}, true},
		{"ipv6 string for port", fields{"2606:4700:4700:foo"}, true},
		{"ipv6 port out of range high", fields{"2606:4700:4700::1111:65536"}, true},
		{"ipv6 port out of range low", fields{"2606:4700:4700::1111:0"}, true},

		// hostname cases
		{"hostname with port", fields{"foo:53"}, false},
		{"hostname without port", fields{"foo"}, true},
		{"hostname port num missing", fields{"foo:"}, true},
		{"hostname string for port", fields{"foo:bar"}, true},
		{"hostname port out of range high", fields{"foo:65536"}, true},
		{"hostname port out of range low", fields{"foo:0"}, true},

		// fqdn cases
		{"fqdn with port", fields{"bar.foo.baz:53"}, false},
		{"fqdn without port", fields{"bar.foo.baz"}, true},
		{"fqdn port num missing", fields{"bar.foo.baz:"}, true},
		{"fqdn string for port", fields{"bar.foo.baz:bar"}, true},
		{"fqdn port out of range high", fields{"bar.foo.baz:65536"}, true},
		{"fqdn port out of range low", fields{"bar.foo.baz:0"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := DNSConf{
				Server: tt.fields.Server,
			}
			if err := c.validateServer(); (err != nil) != tt.wantErr {
				t.Errorf("DNSConf.validateServer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDNSConf_validateQType(t *testing.T) {
	type fields struct {
		QType string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		// valid
		{"A", fields{"A"}, false},
		{"AAAA", fields{"AAAA"}, false},
		{"TXT", fields{"TXT"}, false},
		// invalid
		{"AAA", fields{"AAA"}, true},
		{"TXTT", fields{"TXTT"}, true},
		{"D", fields{"D"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := DNSConf{
				QType: tt.fields.QType,
			}
			if err := c.validateQType(); (err != nil) != tt.wantErr {
				t.Errorf("DNSConf.validateQType() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDNSConf_validateProto(t *testing.T) {
	type fields struct {
		Proto string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		// valid
		{"tcp", fields{"tcp"}, false},
		{"udp", fields{"udp"}, false},
		// invalid
		{"foo", fields{"foo"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := DNSConf{
				Proto: tt.fields.Proto,
			}
			if err := c.validateProto(); (err != nil) != tt.wantErr {
				t.Errorf("DNSConf.validateProto() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
