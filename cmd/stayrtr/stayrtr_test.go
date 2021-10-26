package main

import (
	"net"
	"testing"

	rtr "github.com/bgp/stayrtr/lib"
	"github.com/bgp/stayrtr/prefixfile"
	"github.com/google/go-cmp/cmp"
)

func TestProcessData(t *testing.T) {
	var stuff []prefixfile.VRPJson
	stuff = append(stuff,
		prefixfile.VRPJson{
			Prefix: "192.168.0.0/24",
			Length: 24,
			ASN:    123,
			TA:     "testrir",
		},
		prefixfile.VRPJson{
			Prefix: "192.168.0.0/24",
			Length: 24,
			TA:     "testrir",
		},
		prefixfile.VRPJson{
			Prefix: "2001:db8::/32",
			Length: 33,
			ASN:    "AS123",
			TA:     "testrir",
		},
		prefixfile.VRPJson{
			Prefix: "192.168.1.0/24",
			Length: 25,
			ASN:    123,
			TA:     "testrir",
		},
		// Invalid. Length is 0
		prefixfile.VRPJson{
			Prefix: "192.168.1.0/24",
			Length: 0,
			ASN:    123,
			TA:     "testrir",
		},
		// Invalid. Length less than prefix length
		prefixfile.VRPJson{
			Prefix: "192.168.1.0/24",
			Length: 16,
			ASN:    123,
			TA:     "testrir",
		},
		// Invalid. 129 is invalid for IPv6
		prefixfile.VRPJson{
			Prefix: "2001:db8::/32",
			Length: 129,
			ASN:    123,
			TA:     "testrir",
		},
		// Invalid. 33 is invalid for IPv4
		prefixfile.VRPJson{
			Prefix: "192.168.1.0/24",
			Length: 33,
			ASN:    123,
			TA:     "testrir",
		},
		// Invalid. Not a prefix
		prefixfile.VRPJson{
			Prefix: "192.168.1.0",
			Length: 24,
			ASN:    123,
			TA:     "testrir",
		},
		// Invalid. Not a prefix
		prefixfile.VRPJson{
			Prefix: "👻",
			Length: 24,
			ASN:    123,
			TA:     "testrir",
		},
		// Invalid. Invalid ASN string
		prefixfile.VRPJson{
			Prefix: "192.168.1.0/22",
			Length: 22,
			ASN:    "ASN123",
			TA:     "testrir",
		},
	)
	got, count, v4count, v6count := processData(stuff)
	want := []rtr.VRP{
		{
			Prefix: MustParseIPNet("192.168.0.0/24"),
			MaxLen: 24,
			ASN:    123,
		},
		{
			Prefix: MustParseIPNet("2001:db8::/32"),
			MaxLen: 33,
			ASN:    123,
		},
		{
			Prefix: MustParseIPNet("192.168.1.0/24"),
			MaxLen: 25,
			ASN:    123,
		},
	}
	if count != 3 || v4count != 2 || v6count != 1 {
		t.Errorf("Wanted count = 3, v4count = 2, v6count = 1, but got %d, %d, %d", count, v4count, v6count)
	}

	if !cmp.Equal(got, want) {
		t.Errorf("Want (%+v), Got (%+v)", want, got)
	}
}

// MustParseIPNet is a test helper function to return a net.IPNet
// This should only be called in test code, and it'll panic on test set up
// if unable to parse.
func MustParseIPNet(prefix string) net.IPNet {
	_, ipnet, err := net.ParseCIDR(prefix)
	if err != nil {
		panic(err)
	}
	return *ipnet
}
