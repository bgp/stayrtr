package rtrlib

import (
	"runtime"
	"testing"
	"unsafe"

	"github.com/google/go-cmp/cmp"
)

func TestPDUPrefixStructSize(t *testing.T) {
	if a := runtime.GOARCH; a != "amd64" {
		t.Skipf("skipping, running on %s but this test is hard-coded for amd64 architecture", a)
	}

	// This test verifies that the size of PDUIPv{4,6}Prefix and its component structures
	// do not change unexpectedly due to other code modifications.
	//
	// For reference, the tool structlayout can be used to examine struct sizes
	// and structlayout-optimize to recommend ordering of members to minimize memory utilization.
	// Whenever a constant is changed here, be sure to update the associated
	// comment with the output of the tools.
	//
	// $ go install honnef.co/go/tools/cmd/structlayout@latest
	// $ go install honnef.co/go/tools/cmd/structlayout-optimize@latest

	const (
		// $ structlayout . PDUIPv4Prefix
		// PDUIPv4Prefix.Prefix.ip.addr.hi uint64: 0-8 (size 8, align 8)
		// PDUIPv4Prefix.Prefix.ip.addr.lo uint64: 8-16 (size 8, align 8)
		// PDUIPv4Prefix.Prefix.ip.z *internal/intern.Value: 16-24 (size 8, align 8)
		// PDUIPv4Prefix.Prefix.bitsPlusOne uint8: 24-25 (size 1, align 1)
		// padding: 25-32 (size 7, align 0)
		// PDUIPv4Prefix.ASN uint32: 32-36 (size 4, align 4)
		// PDUIPv4Prefix.Version uint8: 36-37 (size 1, align 1)
		// PDUIPv4Prefix.MaxLen uint8: 37-38 (size 1, align 1)
		// PDUIPv4Prefix.Flags uint8: 38-39 (size 1, align 1)
		// padding: 39-40 (size 1, align 0)
		//
		// $ structlayout . PDUIPv6Prefix
		// PDUIPv6Prefix.Prefix.ip.addr.hi uint64: 0-8 (size 8, align 8)
		// PDUIPv6Prefix.Prefix.ip.addr.lo uint64: 8-16 (size 8, align 8)
		// PDUIPv6Prefix.Prefix.ip.z *internal/intern.Value: 16-24 (size 8, align 8)
		// PDUIPv6Prefix.Prefix.bitsPlusOne uint8: 24-25 (size 1, align 1)
		// padding: 25-32 (size 7, align 0)
		// PDUIPv6Prefix.ASN uint32: 32-36 (size 4, align 4)
		// PDUIPv6Prefix.Version uint8: 36-37 (size 1, align 1)
		// PDUIPv6Prefix.MaxLen uint8: 37-38 (size 1, align 1)
		// PDUIPv6Prefix.Flags uint8: 38-39 (size 1, align 1)
		// padding: 39-40 (size 1, align 0)
		pduIPv4PrefixSize = 40
		pduIPv6PrefixSize = 40
	)

	if diff := cmp.Diff(int(unsafe.Sizeof(PDUIPv4Prefix{})), pduIPv4PrefixSize); diff != "" {
		t.Fatalf("unexpected PDUIPv4Prefix struct size (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(int(unsafe.Sizeof(PDUIPv6Prefix{})), pduIPv6PrefixSize); diff != "" {
		t.Fatalf("unexpected PDUIPv6Prefix struct size (-want +got):\n%s", diff)
	}
}
