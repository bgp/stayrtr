package prefixfile

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeJSONSlurm(t *testing.T) {
	json, err := os.Open("slurm.json")
	if err != nil {
		panic(err)
	}
	decoded, err := DecodeJSONSlurm(json)
	if err != nil {
		t.Errorf("Unable to decode json: %v", err)
	}
	assert.Nil(t, err)
	asn, _ := decoded.ValidationOutputFilters.PrefixFilters[1].GetASN()
	_, asnEmpty := decoded.ValidationOutputFilters.PrefixFilters[0].GetASN()
	assert.Equal(t, uint32(64496), asn)
	assert.True(t, asnEmpty)
	assert.Equal(t, "192.0.2.0/24", decoded.ValidationOutputFilters.PrefixFilters[0].Prefix)
}

func TestFilterOnVRPs(t *testing.T) {
	vrps := []VRPJson{
		{
			ASN:    uint32(65001),
			Prefix: "192.168.0.0/25",
			Length: 25,
		},
		{
			ASN:    uint32(65002),
			Prefix: "192.168.1.0/24",
			Length: 24,
		},
		{
			ASN:    uint32(65003),
			Prefix: "192.168.2.0/24",
			Length: 24,
		},
		{
			ASN:    uint32(65004),
			Prefix: "10.0.0.0/24",
			Length: 24,
		},
		{
			ASN:    uint32(65005),
			Prefix: "10.1.0.0/24",
			Length: 16, // this VRP is broken, maxlength can't be smaller than plen
		},
	}

	slurm := SlurmValidationOutputFilters{
		PrefixFilters: []SlurmPrefixFilter{
			{
				Prefix: "10.0.0.0/8",
			},
			{
				ASN:    uint32(65001),
				Prefix: "192.168.0.0/24",
			},
			{
				ASN: uint32(65002),
			},
		},
	}
	added, removed := slurm.FilterOnVRPs(vrps)
	assert.Len(t, added, 1)
	assert.Len(t, removed, 4)
	assert.Equal(t, uint32(65001), removed[0].GetASN())
	assert.Equal(t, uint32(65005), removed[3].GetASN())
}

func TestAssertVRPs(t *testing.T) {
	slurm := SlurmLocallyAddedAssertions{
		PrefixAssertions: []SlurmPrefixAssertion{
			{
				ASN:     uint32(65001),
				Prefix:  "10.0.0.0/8",
				Comment: "Hello",
			},
			{
				ASN:    uint32(65001),
				Prefix: "192.168.0.0/24",
			},
			{
				ASN:             uint32(65003),
				Prefix:          "192.168.0.0/25",
				MaxPrefixLength: 26,
			},
		},
	}
	vrps := slurm.AssertVRPs()
	assert.Len(t, vrps, 3)
}
