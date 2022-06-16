// rfc8416

package cache

import (
	"encoding/json"
	"io"
	"net"
)

type SlurmPrefixFilter struct {
	Prefix  string
	ASN     interface{}
	Comment string
}

func (pf *SlurmPrefixFilter) GetASN() (uint32, bool) {
	if pf.ASN == nil {
		return 0, true
	} else {
		switch asn := pf.ASN.(type) {
		case json.Number:
			c, _ := asn.Int64()
			return uint32(c), false
		case int:
			return uint32(asn), false
		case uint32:
			return asn, false
		default:
			return 0, true
		}
	}
}

func (pf *SlurmPrefixFilter) GetPrefix() *net.IPNet {
	_, prefix, _ := net.ParseCIDR(pf.Prefix)
	return prefix
}

type SlurmValidationOutputFilters struct {
	PrefixFilters []SlurmPrefixFilter
}

type SlurmPrefixAssertion struct {
	Prefix          string
	ASN             uint32
	MaxPrefixLength int
	Comment         string
}

func (pa *SlurmPrefixAssertion) GetASN() uint32 {
	return pa.ASN
}

func (pa *SlurmPrefixAssertion) GetPrefix() *net.IPNet {
	_, prefix, _ := net.ParseCIDR(pa.Prefix)
	return prefix
}

func (pa *SlurmPrefixAssertion) GetMaxLen() int {
	return pa.MaxPrefixLength
}

type SlurmLocallyAddedAssertions struct {
	PrefixAssertions []SlurmPrefixAssertion
}

type SlurmConfig struct {
	SlurmVersion            int
	ValidationOutputFilters SlurmValidationOutputFilters
	LocallyAddedAssertions  SlurmLocallyAddedAssertions
}

func DecodeJSONSlurm(buf io.Reader) (*SlurmConfig, error) {
	slurm := &SlurmConfig{}
	dec := json.NewDecoder(buf)
	dec.UseNumber()
	err := dec.Decode(slurm)
	if err != nil {
		return nil, err
	}
	return slurm, nil
}

func (s *SlurmValidationOutputFilters) FilterOnVRPs(vrps []VRPJson) ([]VRPJson, []VRPJson) {
	added := make([]VRPJson, 0)
	removed := make([]VRPJson, 0)
	if s.PrefixFilters == nil || len(s.PrefixFilters) == 0 {
		return vrps, removed
	}
	for _, vrp := range vrps {
		rPrefix := vrp.GetPrefix()
		var rIPStart net.IP
		var rIPEnd net.IP
		if rPrefix != nil {
			rIPStart = rPrefix.IP.To16()
			rIPEnd = GetIPBroadcast(*rPrefix).To16()
		}

		var wasRemoved bool
		for _, filter := range s.PrefixFilters {
			fPrefix := filter.GetPrefix()
			fASN, fASNEmpty := filter.GetASN()
			match := true
			if match && fPrefix != nil && rPrefix != nil {

				if !(fPrefix.Contains(rIPStart) && fPrefix.Contains(rIPEnd)) {
					match = false
				}
			}
			if match && !fASNEmpty {
				if vrp.GetASN() != fASN {
					match = false
				}
			}
			if match {
				removed = append(removed, vrp)
				wasRemoved = true
				break
			}
		}

		if !wasRemoved {
			added = append(added, vrp)
		}
	}
	return added, removed
}

func (s *SlurmConfig) FilterOnVRPs(vrps []VRPJson) ([]VRPJson, []VRPJson) {
	return s.ValidationOutputFilters.FilterOnVRPs(vrps)
}

func (s *SlurmLocallyAddedAssertions) AssertVRPs() []VRPJson {
	vrps := make([]VRPJson, 0)
	if s.PrefixAssertions == nil || len(s.PrefixAssertions) == 0 {
		return vrps
	}
	for _, assertion := range s.PrefixAssertions {
		prefix := assertion.GetPrefix()
		if prefix == nil {
			continue
		}
		size, _ := prefix.Mask.Size()
		maxLength := assertion.MaxPrefixLength
		if assertion.MaxPrefixLength <= size {
			maxLength = size
		}
		vrps = append(vrps, VRPJson{
			ASN:    uint32(assertion.ASN),
			Prefix: assertion.Prefix,
			Length: uint8(maxLength),
			TA:     assertion.Comment,
		})
	}
	return vrps
}

func (s *SlurmConfig) AssertVRPs() []VRPJson {
	return s.LocallyAddedAssertions.AssertVRPs()
}

func (s *SlurmConfig) FilterAssert(vrps []VRPJson) []VRPJson {
	a, _ := s.FilterOnVRPs(vrps)
	b := s.AssertVRPs()
	return append(a, b...)
}
