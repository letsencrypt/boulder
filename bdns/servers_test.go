package bdns

import (
	"testing"
)

func Test_validateServerAddress(t *testing.T) {
	type args struct {
		server string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// ipv4 cases
		{"ipv4 with port", args{"1.1.1.1:53"}, false},
		// sad path
		{"ipv4 without port", args{"1.1.1.1"}, true},
		{"ipv4 port num missing", args{"1.1.1.1:"}, true},
		{"ipv4 string for port", args{"1.1.1.1:foo"}, true},
		{"ipv4 port out of range high", args{"1.1.1.1:65536"}, true},
		{"ipv4 port out of range low", args{"1.1.1.1:0"}, true},

		// ipv6 cases
		{"ipv6 with port", args{"[2606:4700:4700::1111]:53"}, false},
		// sad path
		{"ipv6 sans brackets", args{"2606:4700:4700::1111:53"}, true},
		{"ipv6 without port", args{"[2606:4700:4700::1111]"}, true},
		{"ipv6 port num missing", args{"[2606:4700:4700::1111]:"}, true},
		{"ipv6 string for port", args{"[2606:4700:4700::1111]:foo"}, true},
		{"ipv6 port out of range high", args{"[2606:4700:4700::1111]:65536"}, true},
		{"ipv6 port out of range low", args{"[2606:4700:4700::1111]:0"}, true},

		// hostname cases
		{"hostname with port", args{"foo:53"}, false},
		// sad path
		{"hostname without port", args{"foo"}, true},
		{"hostname port num missing", args{"foo:"}, true},
		{"hostname string for port", args{"foo:bar"}, true},
		{"hostname port out of range high", args{"foo:65536"}, true},
		{"hostname port out of range low", args{"foo:0"}, true},

		// fqdn cases
		{"fqdn with port", args{"bar.foo.baz:53"}, false},
		// sad path
		{"fqdn without port", args{"bar.foo.baz"}, true},
		{"fqdn port num missing", args{"bar.foo.baz:"}, true},
		{"fqdn string for port", args{"bar.foo.baz:bar"}, true},
		{"fqdn port out of range high", args{"bar.foo.baz:65536"}, true},
		{"fqdn port out of range low", args{"bar.foo.baz:0"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateServerAddress(tt.args.server)
			if (err != nil) != tt.wantErr {
				t.Errorf("formatServer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_resolveDNSAuthority(t *testing.T) {
	type args struct {
		d string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"IP4 with port", args{"10.10.10.10:53"}, "10.10.10.10:53", false},
		{"IP4 without port", args{"10.10.10.10"}, "10.10.10.10:53", false},
		{"IP6 with port and brackets", args{"[2606:4700:4700::1111]:53"}, "[2606:4700:4700::1111]:53", false},
		{"IP6 without port", args{"2606:4700:4700::1111"}, "[2606:4700:4700::1111]:53", false},
		{"IP6 with brackets without port", args{"[2606:4700:4700::1111]"}, "", true},
		{"hostname with port", args{"localhost:53"}, "127.0.0.1:53", false},
		{"hostname without port", args{"localhost"}, "127.0.0.1:53", false},
		{"malformed hostname with port", args{"localhost:foo"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveDNSAuthority(tt.args.d)
			if err != nil && !tt.wantErr {
				t.Errorf("resolveDNSAuthority() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("resolveDNSAuthority() = %v, want %v", got, tt.want)
			}
		})
	}
}
