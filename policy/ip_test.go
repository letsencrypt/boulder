package policy

import (
	"net"
	"testing"
)

func TestIsReservedIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"192.168.254.254", true},
		{"10.255.0.3", true},
		{"172.16.255.255", true},
		{"172.31.255.255", true},
		{"128.0.0.1", false},
		{"192.169.255.255", false},
		{"9.255.0.255", false},
		{"172.32.255.255", false},

		{"::0", true},
		{"::1", true},
		{"::2", false},

		{"fe80::1", true},
		{"febf::1", true},
		{"fec0::1", false},
		{"feff::1", false},

		{"ff00::1", true},
		{"ff10::1", true},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true},

		{"2002::", true},
		{"2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true},
		{"0100::", true},
		{"0100::0000:ffff:ffff:ffff:ffff", true},
		{"0100::0001:0000:0000:0000:0000", false},
	}

	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			t.Parallel()
			reserved, name, err := IsReservedIP(net.ParseIP(tc.ip))
			if err != nil {
				t.Error(err)
			}
			if reserved != tc.want {
				t.Errorf("Got %#v (%#v), but want %#v", reserved, name, tc.want)
			}
		})
	}
}
