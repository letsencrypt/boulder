package internal

import "net"

// checkInternalIP verifies is an IP address in a registered internal range.
// TODO: Check if we need to verify any IPv6 ranges
// TODO: We should also check for special purpose IP ranges, we might want to do that in a specific function
func checkInternalIP(ip net.IP) bool {
	var privIPSpace []net.IPNet
	// 10.0.0.0/8
	privIPSpace = append(privIPSpace, net.IPNet{
		IP:   net.IP{0xa, 0x0, 0x0, 0x0},
		Mask: net.IPMask{0xff, 0x0, 0x0, 0x0},
	})
	// 172.16.0.0/12"
	privIPSpace = append(privIPSpace, net.IPNet{
		IP:   net.IP{0xac, 0x10, 0x0, 0x0},
		Mask: net.IPMask{0xff, 0xf0, 0x0, 0x0},
	})
	// 192.168.0.0/16
	privIPSpace = append(privIPSpace, net.IPNet{
		IP:   net.IP{0xc0, 0xa8, 0x0, 0x0},
		Mask: net.IPMask{0xff, 0xff, 0x0, 0x0},
	})

	for _, ipSpace := range privIPSpace {
		if ipSpace.Contains(ip) {
			return true
		}
	}
	return false
}
