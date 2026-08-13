package ratelimit

import "testing"

func TestSubnet(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "ipv4 bare groups to /24",
			in:   "203.0.113.5",
			want: "203.0.113.0/24",
		},
		{
			name: "ipv4 with port strips port and groups to /24",
			in:   "203.0.113.200:54321",
			want: "203.0.113.0/24",
		},
		{
			name: "two ipv4 in same /24 share a bucket",
			in:   "203.0.113.250",
			want: "203.0.113.0/24",
		},
		{
			name: "ipv6 bare groups to /48",
			in:   "2001:db8:abcd:1234::1",
			want: "2001:db8:abcd::/48",
		},
		{
			name: "ipv6 with port strips port and groups to /48",
			in:   "[2001:db8:abcd:ffff::9]:443",
			want: "2001:db8:abcd::/48",
		},
		{
			name: "ipv4-mapped ipv6 folds back to native /24",
			in:   "::ffff:203.0.113.5",
			want: "203.0.113.0/24",
		},
		{
			name: "unparseable source fails closed to a stable literal bucket",
			in:   "not-an-ip",
			want: "invalid/not-an-ip",
		},
		{
			name: "empty source fails closed",
			in:   "",
			want: "invalid/",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Subnet(tc.in); got != tc.want {
				t.Errorf("Subnet(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestSubnetGroupsWholeAllocation confirms the whole-allocation grouping that
// makes the per-subnet limit effective: distinct addresses inside one /24 (IPv4)
// or /48 (IPv6) must collapse to a single bucket key so an attacker rotating
// addresses within an allocation cannot multiply their send budget.
func TestSubnetGroupsWholeAllocation(t *testing.T) {
	if a, b := Subnet("198.51.100.1"), Subnet("198.51.100.254"); a != b {
		t.Errorf("addresses in the same /24 mapped to different buckets: %q vs %q", a, b)
	}
	if a, b := Subnet("2001:db8:1:2::1"), Subnet("2001:db8:1:9999::abcd"); a != b {
		t.Errorf("addresses in the same /48 mapped to different buckets: %q vs %q", a, b)
	}
	if a, b := Subnet("203.0.113.1"), Subnet("203.0.114.1"); a == b {
		t.Errorf("addresses in different /24s collapsed to one bucket: %q", a)
	}
}

func TestSubnetOversizedInputTruncated(t *testing.T) {
	longIP := string(make([]byte, 500))
	got := Subnet(longIP)
	if len(got) > 200 {
		t.Errorf("expected Subnet output length <= 200, got %d", len(got))
	}
}
