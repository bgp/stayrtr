package prefixfile

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type VRPJson struct {
	Prefix  string      `json:"prefix"`
	Length  uint8       `json:"maxLength"`
	ASN     interface{} `json:"asn"`
	TA      string      `json:"ta,omitempty"`
	Expires *int64      `json:"expires,omitempty"`
}

type MetaData struct {
	Counts        int    `json:"vrps"`
	CountASPAs    int    `json:"aspas"`
	CountBgpSecKeys int  `json:"aspas"`
	Buildtime     string `json:"buildtime,omitempty"`
	GeneratedUnix *int64 `json:"generated,omitempty"`
}

func (md MetaData) GetBuildTime() time.Time {
	bt, err := time.Parse(time.RFC3339, md.Buildtime)
	if err != nil {
		return time.Time{}
	}
	return bt
}

type VRPList struct {
	Metadata   MetaData                    `json:"metadata,omitempty"`
	Data       []VRPJson                   `json:"roas"` // for historical reasons this is called 'roas', but should've been called vrps
	BgpSecKeys []BgpSecKeyJson             `json:"bgpsec_keys,omitempty"`
	ASPA       *ProviderAuthorizationsJson `json:"provider_authorizations,omitempty"`
}

type BgpSecKeyJson struct {
	Asn     uint32  `json:"asn"`
	Expires *int64  `json:"expires,omitempty"`
	Ta      string  `json:"ta,omitempty"`

	// Base32 encoded, but encoding/json handles this for us
	// Example: MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4FxJr0n2bux1uX1Evl+QWwZYvIadPjLuFX2mxqKuAGUhKnr7VLLDgrE++l9p5eH2kWTNVAN22FUU3db/RKpE2w==
	Pubkey []byte `json:"pubkey"`
	// Base16 encoded, we need to decode this ourself
	// Example: 510F485D29A29DB7B515F9C478F8ED3CB7AA7D23
	Ski string `json:"ski"`
}

// ASPA
type ProviderAuthorizationsJson struct {
	IPv4 []ASPAJson `json:"ipv4"`
	IPv6 []ASPAJson `json:"ipv6"`
}

type ASPAJson struct {
	CustomerAsid uint32   `json:"customer_asid"`
	Expires      *int64   `json:"expires,omitempty"`
	Providers    []uint32 `json:"providers"`
}

func (vrp *VRPJson) GetASN2() (uint32, error) {
	switch asnc := vrp.ASN.(type) {
	case string:
		asnStr := strings.TrimLeft(asnc, "aAsS")
		asnInt, err := strconv.ParseUint(asnStr, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("could not decode ASN string: %v", vrp.ASN)
		}
		asn := uint32(asnInt)
		return asn, nil
	case uint32:
		return asnc, nil
	case float64:
		return uint32(asnc), nil
	case int:
		return uint32(asnc), nil
	default:
		return 0, fmt.Errorf("could not decode ASN: %v", vrp.ASN)
	}
}

func (vrp *VRPJson) GetASN() uint32 {
	asn, _ := vrp.GetASN2()
	return asn
}

func (vrp *VRPJson) GetPrefix2() (*net.IPNet, error) {
	_, prefix, err := net.ParseCIDR(vrp.Prefix)
	if err != nil {
		return nil, fmt.Errorf("could not decode prefix: %v", vrp.Prefix)
	}
	return prefix, nil
}

func (vrp *VRPJson) GetPrefix() *net.IPNet {
	prefix, _ := vrp.GetPrefix2()
	return prefix
}

func (vrp *VRPJson) GetMaxLen() int {
	return int(vrp.Length)
}

func (vrp *VRPJson) String() string {
	return fmt.Sprintf("%v/%v/%v", vrp.Prefix, vrp.Length, vrp.ASN)
}

func GetIPBroadcast(ipnet net.IPNet) net.IP {
	br := make([]byte, len(ipnet.IP))
	for i := 0; i < len(ipnet.IP); i++ {
		br[i] = ipnet.IP[i] | (^ipnet.Mask[i])
	}
	return net.IP(br)
}
