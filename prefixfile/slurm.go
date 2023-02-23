// rfc8416 and draft-sidrops-aspa-slurm

package prefixfile

import (
	"encoding/json"
	"io"
	"net"
)

type SlurmPrefixFilter struct {
	Prefix  string
	ASN     *uint32 `json:"asn,omitempty"`
	Comment string
}

type SlurmBGPsecFilter struct {
	ASN     uint32 `json:"asn"`
	Comment string `json:"comment"`
}

type SlurmASPAFilter struct {
	Afi          string `json:"afi"`
	Comment      string `json:"comment"`
	CustomerASid uint32 `json:"customer_asid"`
}

func (pf *SlurmPrefixFilter) GetASN() (uint32, bool) {
	if pf.ASN == nil {
		return 0, true
	} else {
		return *pf.ASN, false
	}
}

func (pf *SlurmPrefixFilter) GetPrefix() *net.IPNet {
	_, prefix, _ := net.ParseCIDR(pf.Prefix)
	return prefix
}

type SlurmValidationOutputFilters struct {
	PrefixFilters []SlurmPrefixFilter
	BgpsecFilters []SlurmBGPsecFilter
	AspaFilters   []SlurmASPAFilter
}

type SlurmPrefixAssertion struct {
	Prefix          string
	ASN             uint32
	MaxPrefixLength int
	Comment         string
}

type SlurmBGPsecAssertion struct {
	SKI             []byte `json:"SKI"`
	ASN             uint32 `json:"asn"`
	Comment         string `json:"comment"`
	RouterPublicKey []byte `json:"routerPublicKey"`
}

type SlurmASPAAssertion struct {
	Afi           string   `json:"afi"`
	Comment       string   `json:"comment"`
	CustomerASNid uint32   `json:"customer_asid"`
	ProviderSet   []uint32 `json:"provider_set"`
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
	BgpsecAssertions []SlurmBGPsecAssertion
	AspaAssertions   []SlurmASPAAssertion
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
