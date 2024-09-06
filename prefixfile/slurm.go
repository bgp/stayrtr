// rfc8416

package prefixfile

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/netip"
)

type SlurmPrefixFilter struct {
	Prefix  string
	ASN     *uint32 `json:"asn,omitempty"`
	Comment string
}

type SlurmBGPsecFilter struct {
	ASN     *uint32 `json:"asn,omitempty"`
	SKI     []byte  `json:"SKI,omitempty"`
	Comment string  `json:"comment"`
}

func (pf *SlurmPrefixFilter) GetASN() (uint32, bool) {
	if pf.ASN == nil {
		return 0, true
	} else {
		return *pf.ASN, false
	}
}

func (pf *SlurmPrefixFilter) GetPrefix() netip.Prefix {
	prefix, _ := netip.ParsePrefix(pf.Prefix)
	return prefix
}

type SlurmValidationOutputFilters struct {
	PrefixFilters []SlurmPrefixFilter
	BgpsecFilters []SlurmBGPsecFilter
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

func (s *SlurmValidationOutputFilters) FilterOnVRPs(vrps []VRPJson) (added, removed []VRPJson) {
	added = make([]VRPJson, 0)
	removed = make([]VRPJson, 0)
	if s.PrefixFilters == nil || len(s.PrefixFilters) == 0 {
		return vrps, removed
	}
	for _, vrp := range vrps {
		rPrefix := vrp.GetPrefix()

		var wasRemoved bool
		for _, filter := range s.PrefixFilters {
			fPrefix := filter.GetPrefix()
			fASN, fASNEmpty := filter.GetASN()
			match := true
			if match && fPrefix.IsValid() && rPrefix.IsValid() {

				if !(fPrefix.Overlaps(rPrefix) &&
				    fPrefix.Bits() <= rPrefix.Bits()) {
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

func (s *SlurmValidationOutputFilters) FilterOnBRKs(brks []BgpSecKeyJson) (added, removed []BgpSecKeyJson) {
	added = make([]BgpSecKeyJson, 0)
	removed = make([]BgpSecKeyJson, 0)
	if s.BgpsecFilters == nil || len(s.BgpsecFilters) == 0 {
		return brks, removed
	}
	for _, brk := range brks {
		var skiCache []byte
		var wasRemoved bool
		for _, filter := range s.BgpsecFilters {
			if filter.ASN != nil {
				if brk.Asn == *filter.ASN {
					if len(filter.SKI) != 0 {
						// We need to compare the SKIs then
						if skiCache == nil { // We have not yet decoded the ski hex
							var err error
							skiCache, err = hex.DecodeString(brk.Ski)
							if err != nil {
								// Ski could not be decoded, so we can't filter
								continue
							}
						}
						if bytes.Equal(filter.SKI, skiCache) {
							removed = append(removed, brk)
							wasRemoved = true
							break
						}
					} else {
						// Only a ASN match was needed
						removed = append(removed, brk)
						wasRemoved = true
						break
					}
				}
			}

			if len(filter.SKI) != 0 && filter.ASN == nil {
				// We need to compare just the SKIs then
				if skiCache == nil { // We have not yet decoded the ski hex
					var err error
					skiCache, err = hex.DecodeString(brk.Ski)
					if err != nil {
						// Ski could not be decoded, so we can't filter
						continue
					}
				}
				if bytes.Equal(filter.SKI, skiCache) {
					removed = append(removed, brk)
					wasRemoved = true
					break
				}
			}
		}

		if !wasRemoved {
			added = append(added, brk)
		}
	}
	return added, removed
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

func (s *SlurmLocallyAddedAssertions) AssertBRKs() []BgpSecKeyJson {
	brks := make([]BgpSecKeyJson, 0)

	if s.BgpsecAssertions == nil || len(s.BgpsecAssertions) == 0 {
		return brks
	}
	for _, assertion := range s.BgpsecAssertions {
		hexSki := hex.EncodeToString(assertion.SKI)
		brk := BgpSecKeyJson{
			Asn:    assertion.ASN,
			Pubkey: assertion.RouterPublicKey,
			Ski:    hexSki,
		}
		brks = append(brks, brk)
	}
	return brks
}

func (s *SlurmConfig) GetAssertions() (vrps []VRPJson, BRKs []BgpSecKeyJson) {
	vrps = s.LocallyAddedAssertions.AssertVRPs()
	BRKs = s.LocallyAddedAssertions.AssertBRKs()
	return
}

func (s *SlurmConfig) FilterAssert(vrps []VRPJson, BRKs []BgpSecKeyJson, log Logger) (
	ovrps []VRPJson, oBRKs []BgpSecKeyJson) {
	//
	filteredVRPs, removedVRPs := s.ValidationOutputFilters.FilterOnVRPs(vrps)
	filteredBRKs, removedBRKs := s.ValidationOutputFilters.FilterOnBRKs(BRKs)

	assertVRPs, assertBRKs := s.GetAssertions()

	ovrps = append(filteredVRPs, assertVRPs...)
	oBRKs = append(filteredBRKs, assertBRKs...)

	if log != nil {
		if len(s.ValidationOutputFilters.PrefixFilters) != 0 {
			log.Infof("Slurm VRP filtering: %v kept, %v removed, %v asserted", len(filteredVRPs), len(removedVRPs), len(ovrps))
		}

		if len(s.ValidationOutputFilters.BgpsecFilters) != 0 {
			log.Infof("Slurm Router Key filtering: %v kept, %v removed, %v asserted", len(filteredBRKs), len(removedBRKs), len(oBRKs))
		}
	}
	return
}

type Logger interface {
	Debugf(string, ...interface{})
	Printf(string, ...interface{})
	Warnf(string, ...interface{})
	Errorf(string, ...interface{})
	Infof(string, ...interface{})
}
