package iana

import (
	"net/netip"
	"testing"
)

func TestIsReservedAddr(t *testing.T) {
	t.Parallel()

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
		{"0100::0002:0000:0000:0000:0000", false},
	}

	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			t.Parallel()
			err := IsReservedAddr(netip.MustParseAddr(tc.ip))
			if err != nil && !tc.want {
				t.Error(err)
			}
			if err == nil && tc.want {
				t.Errorf("Wanted error for %#v, got success", tc.ip)
			}
		})
	}
}

func TestIsReservedPrefix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		cidr string
		want bool
	}{
		{"172.16.0.0/12", true},
		{"172.16.0.0/32", true},
		{"172.16.0.1/32", true},
		{"172.31.255.0/24", true},
		{"172.31.255.255/24", true},
		{"172.31.255.255/32", true},
		{"172.32.0.0/24", false},
		{"172.32.0.1/32", false},

		{"100::/64", true},
		{"100::/128", true},
		{"100::1/128", true},
		{"100::1:ffff:ffff:ffff:ffff/128", true},
		{"100:0:0:2::/64", false},
		{"100:0:0:2::1/128", false},
	}

	for _, tc := range cases {
		t.Run(tc.cidr, func(t *testing.T) {
			t.Parallel()
			err := IsReservedPrefix(netip.MustParsePrefix(tc.cidr))
			if err != nil && !tc.want {
				t.Error(err)
			}
			if err == nil && tc.want {
				t.Errorf("Wanted error for %#v, got success", tc.cidr)
			}
		})
	}
}
