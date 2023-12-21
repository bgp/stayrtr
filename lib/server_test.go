package rtrlib

import (
	"fmt"
	"net/netip"
	"runtime"
	"testing"
	"unsafe"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
)

func GenerateVrps(size uint32, offset uint32) []SendableData {
	vrps := make([]SendableData, size)
	for i := uint32(0); i < size; i++ {
		ipFinal := i+offset
		vrps[i] = &VRP{
			Prefix: netip.MustParsePrefix(fmt.Sprintf("fd00::%04x:%04x/128", ipFinal >> 16, ipFinal & 0xffff)),
			MaxLen: 128,
			ASN:    64496,
		}
	}
	return vrps
}

func BaseBench(base int, multiplier int) {
	benchSize1 := base * multiplier
	newVrps := GenerateVrps(uint32(benchSize1), uint32(0))
	benchSize2 := base
	prevVrps := GenerateVrps(uint32(benchSize2), uint32(benchSize1-benchSize2/2))
	ComputeDiff(newVrps, prevVrps, false)
}

func BenchmarkComputeDiff1000x10(b *testing.B) {
	BaseBench(1000, 10)
}

func BenchmarkComputeDiff10000x10(b *testing.B) {
	BaseBench(10000, 10)
}

func BenchmarkComputeDiff100000x1(b *testing.B) {
	BaseBench(100000, 1)
}

func TestComputeDiff(t *testing.T) {
	newVrps := []VRP{
		{
			Prefix: netip.MustParsePrefix("fd00::3/128"),
			MaxLen: 128,
			ASN:    65003,
		},
		{
			Prefix: netip.MustParsePrefix("fd00::2/128"),
			MaxLen: 128,
			ASN:    65002,
		},
	}
	prevVrps := []VRP{
		{
			Prefix: netip.MustParsePrefix("fd00::1/128"),
			MaxLen: 128,
			ASN:    65001,
		},
		{
			Prefix: netip.MustParsePrefix("fd00::2/128"),
			MaxLen: 128,
			ASN:    65002,
		},
	}

	newVrpsSD, prevVrpsAsSD := make([]SendableData, 0), make([]SendableData, 0)
	for _, v := range newVrps {
		newVrpsSD = append(newVrpsSD, v.Copy())
	}
	for _, v := range prevVrps {
		prevVrpsAsSD = append(prevVrpsAsSD, v.Copy())
	}

	added, removed, unchanged := ComputeDiff(newVrpsSD, prevVrpsAsSD, true)
	assert.Len(t, added, 1)
	assert.Len(t, removed, 1)
	assert.Len(t, unchanged, 1)
	assert.Equal(t, added[0].(*VRP).ASN, uint32(65003))
	assert.Equal(t, removed[0].(*VRP).ASN, uint32(65001))
	assert.Equal(t, unchanged[0].(*VRP).ASN, uint32(65002))
}

func TestApplyDiff(t *testing.T) {
	diff := []VRP{
		{
			Prefix: netip.MustParsePrefix("fd00::3/128"),
			MaxLen: 128,
			ASN:    65003,
			Flags:  FLAG_ADDED,
		},
		{
			Prefix: netip.MustParsePrefix("fd00::2/128"),
			MaxLen: 128,
			ASN:    65002,
			Flags:  FLAG_REMOVED,
		},
		{
			Prefix: netip.MustParsePrefix("fd00::4/128"),
			MaxLen: 128,
			ASN:    65004,
			Flags:  FLAG_REMOVED,
		},
		{
			Prefix: netip.MustParsePrefix("fd00::6/128"),
			MaxLen: 128,
			ASN:    65006,
			Flags:  FLAG_REMOVED,
		},
		{
			Prefix: netip.MustParsePrefix("fd00::7/128"),
			MaxLen: 128,
			ASN:    65007,
			Flags:  FLAG_ADDED,
		},
	}
	prevVrps := []VRP{
		{
			Prefix: netip.MustParsePrefix("fd00::1/128"),
			MaxLen: 128,
			ASN:    65001,
			Flags:  FLAG_ADDED,
		},
		{
			Prefix: netip.MustParsePrefix("fd00::2/128"),
			MaxLen: 128,
			ASN:    65002,
			Flags:  FLAG_ADDED,
		},
		{
			Prefix: netip.MustParsePrefix("fd00::5/128"),
			MaxLen: 128,
			ASN:    65005,
			Flags:  FLAG_REMOVED,
		},
		{
			Prefix: netip.MustParsePrefix("fd00::6/128"),
			MaxLen: 128,
			ASN:    65006,
			Flags:  FLAG_REMOVED,
		},
		{
			Prefix: netip.MustParsePrefix("fd00::7/128"),
			MaxLen: 128,
			ASN:    65007,
			Flags:  FLAG_REMOVED,
		},
	}
	diffSD, prevVrpsAsSD := make([]SendableData, 0), make([]SendableData, 0)
	for _, v := range diff {
		diffSD = append(diffSD, v.Copy())
	}
	for _, v := range prevVrps {
		prevVrpsAsSD = append(prevVrpsAsSD, v.Copy())
	}

	vrps := ApplyDiff(diffSD, prevVrpsAsSD)

	assert.Len(t, vrps, 6)
	assert.Equal(t, vrps[0].(*VRP).ASN, uint32(65001))
	assert.Equal(t, vrps[0].(*VRP).GetFlag(), uint8(FLAG_ADDED))
	assert.Equal(t, vrps[1].(*VRP).ASN, uint32(65005))
	assert.Equal(t, vrps[1].(*VRP).GetFlag(), uint8(FLAG_REMOVED))
	assert.Equal(t, vrps[2].(*VRP).ASN, uint32(65003))
	assert.Equal(t, vrps[2].(*VRP).GetFlag(), uint8(FLAG_ADDED))
	assert.Equal(t, vrps[3].(*VRP).ASN, uint32(65004))
	assert.Equal(t, vrps[3].(*VRP).GetFlag(), uint8(FLAG_REMOVED))
	assert.Equal(t, vrps[4].(*VRP).ASN, uint32(65006))
	assert.Equal(t, vrps[4].(*VRP).GetFlag(), uint8(FLAG_REMOVED))
	assert.Equal(t, vrps[5].(*VRP).ASN, uint32(65007))
	assert.Equal(t, vrps[5].(*VRP).GetFlag(), uint8(FLAG_ADDED))
}

func TestComputeDiffBGPSEC(t *testing.T) {
	newVrps := []BgpsecKey{
		{
			ASN:    65003,
			Pubkey: []byte("hurr"),
			Ski:    []byte("durr"),
		},
		{
			Pubkey: []byte("abc"),
			Ski:    []byte("dce"),
			ASN:    65002,
		},
	}
	prevVrps := []BgpsecKey{
		{
			Pubkey: []byte("murr"),
			Ski:    []byte("durr"),
			ASN:    65001,
		},
		{
			Pubkey: []byte("abc"),
			Ski:    []byte("dce"),
			ASN:    65002,
		},
	}

	newVrpsSD, prevVrpsAsSD := make([]SendableData, 0), make([]SendableData, 0)
	for _, v := range newVrps {
		newVrpsSD = append(newVrpsSD, v.Copy())
	}
	for _, v := range prevVrps {
		prevVrpsAsSD = append(prevVrpsAsSD, v.Copy())
	}

	added, removed, unchanged := ComputeDiff(newVrpsSD, prevVrpsAsSD, true)
	assert.Len(t, added, 1)
	assert.Len(t, removed, 1)
	assert.Len(t, unchanged, 1)
	assert.Equal(t, added[0].(*BgpsecKey).ASN, uint32(65003))
	assert.Equal(t, removed[0].(*BgpsecKey).ASN, uint32(65001))
	assert.Equal(t, unchanged[0].(*BgpsecKey).ASN, uint32(65002))
}

func TestVRPStructSize(t *testing.T) {
	if a := runtime.GOARCH; a != "amd64" {
		t.Skipf("skipping, running on %s but this test is hard-coded for amd64 architecture", a)
	}

	// This test verifies that the size of a VRP and its component structures
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
		// $ structlayout -json . VRP
		// VRP.Prefix.ip.addr.hi uint64: 0-8 (size 8, align 8)
		// VRP.Prefix.ip.addr.lo uint64: 8-16 (size 8, align 8)
		// VRP.Prefix.ip.z *internal/intern.Value: 16-24 (size 8, align 8)
		// VRP.Prefix.bitsPlusOne uint8: 24-25 (size 1, align 1)
		// padding: 25-32 (size 7, align 0)
		// VRP.ASN uint32: 32-36 (size 4, align 4)
		// VRP.MaxLen uint8: 36-37 (size 1, align 1)
		// VRP.Flags uint8: 37-38 (size 1, align 1)
		// padding: 38-40 (size 2, align 0)
		//
		// NOTE: we could actually reduce this to 32 if netip.Prefix
		// were properly aligned. Ex:
		// $ structlayout -json . VRP | structlayout-optimize
		// VRP.Prefix struct: 0-24 (size 24, align 8)
		// VRP.ASN uint32: 24-28 (size 4, align 4)
		// VRP.MaxLen uint8: 28-29 (size 1, align 1)
		// VRP.Flags uint8: 29-30 (size 1, align 1)
		// padding: 30-32 (size 2, align 0)
		//
		vrpSize = 40
	)

	if diff := cmp.Diff(int(unsafe.Sizeof(VRP{})), vrpSize); diff != "" {
		t.Fatalf("unexpected VRPs struct size (-want +got):\n%s", diff)
	}
}
