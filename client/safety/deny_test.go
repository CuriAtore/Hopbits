package safety

import (
	"net/netip"
	"testing"
)

func TestDenied(t *testing.T) {
	cases := []struct {
		addr   string
		denied bool
	}{
		{"1.1.1.1", false},
		{"8.8.8.8", false},
		{"0.1.2.3", true},
		{"10.20.30.40", true},
		{"100.64.0.1", true},
		{"100.100.100.200", true}, // Alibaba metadata, inside CGNAT space
		{"127.0.0.1", true},
		{"169.254.169.254", true}, // cloud metadata
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.32.0.1", false},
		{"192.0.0.192", true},
		{"192.0.2.1", true},
		{"192.168.1.1", true},
		{"198.18.0.1", true},
		{"198.51.100.7", true},
		{"203.0.113.9", true},
		{"224.0.0.251", true},
		{"239.255.255.250", true},
		{"240.0.0.1", true},
		{"255.255.255.255", true},
		{"::ffff:127.0.0.1", true},  // IPv4-mapped loopback
		{"::ffff:8.8.8.8", false},   // IPv4-mapped public
		{"64:ff9b::a00:1", true},    // NAT64 of 10.0.0.1
		{"64:ff9b::808:808", false}, // NAT64 of 8.8.8.8
		{"64:ff9b:1::1", true},
		{"::", true},
		{"::1", true},
		{"fe80::1", true},
		{"fd00:ec2::254", true}, // AWS metadata, inside ULA
		{"fc00::1", true},
		{"ff02::1", true},
		{"2001:db8::1", true},
		{"2001::1", true}, // Teredo
		{"2002:c000:204::1", true},
		{"3fff::1", true},
		{"5f00::1", true},
		{"2606:4700:4700::1111", false},
		{"2a00:1450:4001:80b::200e", false},
	}
	for _, c := range cases {
		got, why := Denied(netip.MustParseAddr(c.addr))
		if got != c.denied {
			t.Errorf("Denied(%s) = %v (%s), want %v", c.addr, got, why, c.denied)
		}
	}
	if denied, _ := Denied(netip.Addr{}); !denied {
		t.Error("invalid address allowed")
	}
	if denied, _ := Denied(netip.MustParseAddr("fe80::1%eth0")); !denied {
		t.Error("zoned address allowed")
	}
}
