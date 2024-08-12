package rtrlib

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

type Logger interface {
	Debugf(string, ...interface{})
	Printf(string, ...interface{})
	Warnf(string, ...interface{})
	Errorf(string, ...interface{})
	Infof(string, ...interface{})
}

const (
	APP_VERSION = "0.6.0"

	// We use the size of the largest sensible PDU.
	//
	// We ignore the theoretically unbounded length of SKIs for router keys.
	// RPs should validate that this has the correct length.
	//
	// Maximum size of ASPA PDU payload:
	// * header + length field: 8 bytes
	// * Customer ASID: 4 bytes
	// * 20,002 providers * 32bit = 80,008 bytes
	messageMaxSize = 80020

	PROTOCOL_VERSION_0 = 0
	PROTOCOL_VERSION_1 = 1
	PROTOCOL_VERSION_2 = 2

	PDU_ID_SERIAL_NOTIFY  = 0
	PDU_ID_SERIAL_QUERY   = 1
	PDU_ID_RESET_QUERY    = 2
	PDU_ID_CACHE_RESPONSE = 3
	PDU_ID_IPV4_PREFIX    = 4
	PDU_ID_IPV6_PREFIX    = 6
	PDU_ID_END_OF_DATA    = 7
	PDU_ID_CACHE_RESET    = 8
	PDU_ID_ROUTER_KEY     = 9
	PDU_ID_ERROR_REPORT   = 10
	PDU_ID_ASPA           = 11

	FLAG_ADDED   = 1
	FLAG_REMOVED = 0

	PDU_ERROR_CORRUPTDATA     = 0
	PDU_ERROR_INTERNALERR     = 1
	PDU_ERROR_NODATA          = 2
	PDU_ERROR_INVALIDREQUEST  = 3
	PDU_ERROR_BADPROTOVERSION = 4
	PDU_ERROR_BADPDUTYPE      = 5
	PDU_ERROR_WITHDRAWUNKNOWN = 6
	PDU_ERROR_DUPANNOUNCE     = 7

	AFI_IPv4 = uint8(0)
	AFI_IPv6 = uint8(1)

	TYPE_UNKNOWN = iota
	TYPE_PLAIN
	TYPE_TLS
	TYPE_SSH
)

type PDU interface {
	Bytes() []byte
	Write(io.Writer)
	String() string
	SetVersion(uint8)
	GetVersion() uint8
	GetType() uint8
}

func TypeToString(t uint8) string {
	switch t {
	case PDU_ID_SERIAL_NOTIFY:
		return "Serial Notify"
	case PDU_ID_SERIAL_QUERY:
		return "Serial Query"
	case PDU_ID_RESET_QUERY:
		return "Reset Query"
	case PDU_ID_CACHE_RESPONSE:
		return "Cache Response"
	case PDU_ID_IPV4_PREFIX:
		return "IPv4 Prefix"
	case PDU_ID_IPV6_PREFIX:
		return "IPv6 Prefix"
	case PDU_ID_END_OF_DATA:
		return "End of Data"
	case PDU_ID_CACHE_RESET:
		return "Cache Reset"
	case PDU_ID_ROUTER_KEY:
		return "Router Key"
	case PDU_ID_ERROR_REPORT:
		return "Error Report"
	case PDU_ID_ASPA:
		return "ASPA PDU"
	default:
		return fmt.Sprintf("Unknown type %d", t)
	}
}

func IsCorrectPDUVersion(pdu PDU, version uint8) bool {
	if version > 1 {
		return false
	}
	switch pdu.(type) {
	case *PDURouterKey:
		if version == 0 {
			return false
		}
	}
	return true
}

type PDUSerialNotify struct {
	Version      uint8
	SessionId    uint16
	SerialNumber uint32
}

func (pdu *PDUSerialNotify) String() string {
	return fmt.Sprintf("PDU Serial Notify v%d (session: %d): serial: %d", pdu.Version, pdu.SessionId, pdu.SerialNumber)
}

func (pdu *PDUSerialNotify) Bytes() []byte {
	b := bytes.NewBuffer([]byte{})
	pdu.Write(b)
	return b.Bytes()
}

func (pdu *PDUSerialNotify) SetVersion(version uint8) {
	pdu.Version = version
}

func (pdu *PDUSerialNotify) GetVersion() uint8 {
	return pdu.Version
}

func (pdu *PDUSerialNotify) GetType() uint8 {
	return PDU_ID_SERIAL_NOTIFY
}

func (pdu *PDUSerialNotify) Write(wr io.Writer) {
	binary.Write(wr, binary.BigEndian, uint8(pdu.Version))
	binary.Write(wr, binary.BigEndian, uint8(PDU_ID_SERIAL_NOTIFY))
	binary.Write(wr, binary.BigEndian, pdu.SessionId)
	binary.Write(wr, binary.BigEndian, uint32(12))
	binary.Write(wr, binary.BigEndian, uint32(pdu.SerialNumber))
}

type PDUSerialQuery struct {
	Version      uint8
	SessionId    uint16
	SerialNumber uint32
}

func (pdu *PDUSerialQuery) String() string {
	return fmt.Sprintf("PDU Serial Query v%d (session: %d): serial: %d", pdu.Version, pdu.SessionId, pdu.SerialNumber)
}

func (pdu *PDUSerialQuery) Bytes() []byte {
	b := bytes.NewBuffer([]byte{})
	pdu.Write(b)
	return b.Bytes()
}

func (pdu *PDUSerialQuery) SetVersion(version uint8) {
	pdu.Version = version
}

func (pdu *PDUSerialQuery) GetVersion() uint8 {
	return pdu.Version
}

func (pdu *PDUSerialQuery) GetType() uint8 {
	return PDU_ID_SERIAL_QUERY
}

func (pdu *PDUSerialQuery) Write(wr io.Writer) {
	binary.Write(wr, binary.BigEndian, uint8(pdu.Version))
	binary.Write(wr, binary.BigEndian, uint8(PDU_ID_SERIAL_QUERY))
	binary.Write(wr, binary.BigEndian, pdu.SessionId)
	binary.Write(wr, binary.BigEndian, uint32(12))
	binary.Write(wr, binary.BigEndian, uint32(pdu.SerialNumber))
}

type PDUResetQuery struct {
	Version uint8
}

func (pdu *PDUResetQuery) String() string {
	return fmt.Sprintf("PDU Reset Query v%d", pdu.Version)
}

func (pdu *PDUResetQuery) Bytes() []byte {
	b := bytes.NewBuffer([]byte{})
	pdu.Write(b)
	return b.Bytes()
}

func (pdu *PDUResetQuery) SetVersion(version uint8) {
	pdu.Version = version
}

func (pdu *PDUResetQuery) GetVersion() uint8 {
	return pdu.Version
}

func (pdu *PDUResetQuery) GetType() uint8 {
	return PDU_ID_RESET_QUERY
}

func (pdu *PDUResetQuery) Write(wr io.Writer) {
	binary.Write(wr, binary.BigEndian, uint8(pdu.Version))
	binary.Write(wr, binary.BigEndian, uint8(PDU_ID_RESET_QUERY))
	binary.Write(wr, binary.BigEndian, uint16(0))
	binary.Write(wr, binary.BigEndian, uint32(8))
}

type PDUCacheResponse struct {
	Version   uint8
	SessionId uint16
}

func (pdu *PDUCacheResponse) String() string {
	return fmt.Sprintf("PDU Cache Response v%d (session: %d)", pdu.Version, pdu.SessionId)
}

func (pdu *PDUCacheResponse) Bytes() []byte {
	b := bytes.NewBuffer([]byte{})
	pdu.Write(b)
	return b.Bytes()
}

func (pdu *PDUCacheResponse) SetVersion(version uint8) {
	pdu.Version = version
}

func (pdu *PDUCacheResponse) GetVersion() uint8 {
	return pdu.Version
}

func (pdu *PDUCacheResponse) GetType() uint8 {
	return PDU_ID_CACHE_RESPONSE
}

func (pdu *PDUCacheResponse) Write(wr io.Writer) {
	binary.Write(wr, binary.BigEndian, uint8(pdu.Version))
	binary.Write(wr, binary.BigEndian, uint8(PDU_ID_CACHE_RESPONSE))
	binary.Write(wr, binary.BigEndian, pdu.SessionId)
	binary.Write(wr, binary.BigEndian, uint32(8))
}

type PDUIPv4Prefix struct {
	Prefix  netip.Prefix
	ASN     uint32
	Version uint8
	MaxLen  uint8
	Flags   uint8
}

func (pdu *PDUIPv4Prefix) String() string {
	return fmt.Sprintf("PDU IPv4 Prefix v%d %s(->/%d), origin: AS%d, flags: %d", pdu.Version, pdu.Prefix.String(), pdu.MaxLen, pdu.ASN, pdu.Flags)
}

func (pdu *PDUIPv4Prefix) Bytes() []byte {
	b := bytes.NewBuffer([]byte{})
	pdu.Write(b)
	return b.Bytes()
}

func (pdu *PDUIPv4Prefix) SetVersion(version uint8) {
	pdu.Version = version
}

func (pdu *PDUIPv4Prefix) GetVersion() uint8 {
	return pdu.Version
}

func (pdu *PDUIPv4Prefix) GetType() uint8 {
	return PDU_ID_IPV4_PREFIX
}

func (pdu *PDUIPv4Prefix) Write(wr io.Writer) {
	binary.Write(wr, binary.BigEndian, uint8(pdu.Version))
	binary.Write(wr, binary.BigEndian, uint8(PDU_ID_IPV4_PREFIX))
	binary.Write(wr, binary.BigEndian, uint16(0))
	binary.Write(wr, binary.BigEndian, uint32(20))
	binary.Write(wr, binary.BigEndian, pdu.Flags)
	binary.Write(wr, binary.BigEndian, uint8(pdu.Prefix.Bits()))
	binary.Write(wr, binary.BigEndian, pdu.MaxLen)
	binary.Write(wr, binary.BigEndian, uint8(0))
	binary.Write(wr, binary.BigEndian, pdu.Prefix.Addr().As4())
	binary.Write(wr, binary.BigEndian, pdu.ASN)
}

type PDUIPv6Prefix struct {
	Prefix  netip.Prefix
	ASN     uint32
	Version uint8
	MaxLen  uint8
	Flags   uint8
}

func (pdu *PDUIPv6Prefix) String() string {
	return fmt.Sprintf("PDU IPv6 Prefix v%d %s(->/%d), origin: AS%d, flags: %d", pdu.Version, pdu.Prefix.String(), pdu.MaxLen, pdu.ASN, pdu.Flags)
}

func (pdu *PDUIPv6Prefix) Bytes() []byte {
	b := bytes.NewBuffer([]byte{})
	pdu.Write(b)
	return b.Bytes()
}

func (pdu *PDUIPv6Prefix) SetVersion(version uint8) {
	pdu.Version = version
}

func (pdu *PDUIPv6Prefix) GetVersion() uint8 {
	return pdu.Version
}

func (pdu *PDUIPv6Prefix) GetType() uint8 {
	return PDU_ID_IPV6_PREFIX
}

func (pdu *PDUIPv6Prefix) Write(wr io.Writer) {
	binary.Write(wr, binary.BigEndian, uint8(pdu.Version))
	binary.Write(wr, binary.BigEndian, uint8(PDU_ID_IPV6_PREFIX))
	binary.Write(wr, binary.BigEndian, uint16(0))
	binary.Write(wr, binary.BigEndian, uint32(32))
	binary.Write(wr, binary.BigEndian, pdu.Flags)
	binary.Write(wr, binary.BigEndian, uint8(pdu.Prefix.Bits()))
	binary.Write(wr, binary.BigEndian, pdu.MaxLen)
	binary.Write(wr, binary.BigEndian, uint8(0))
	binary.Write(wr, binary.BigEndian, pdu.Prefix.Addr().As16())
	binary.Write(wr, binary.BigEndian, pdu.ASN)
}

type PDUEndOfData struct {
	Version      uint8
	SessionId    uint16
	SerialNumber uint32

	RefreshInterval uint32
	RetryInterval   uint32
	ExpireInterval  uint32
}

func (pdu *PDUEndOfData) String() string {
	return fmt.Sprintf("PDU End of Data v%d (session: %d): serial: %d, refresh: %d, retry: %d, expire: %d",
		pdu.Version, pdu.SessionId, pdu.SerialNumber, pdu.RefreshInterval, pdu.RetryInterval, pdu.ExpireInterval)
}

func (pdu *PDUEndOfData) Bytes() []byte {
	b := bytes.NewBuffer([]byte{})
	pdu.Write(b)
	return b.Bytes()
}

func (pdu *PDUEndOfData) SetVersion(version uint8) {
	pdu.Version = version
}

func (pdu *PDUEndOfData) GetVersion() uint8 {
	return pdu.Version
}

func (pdu *PDUEndOfData) GetType() uint8 {
	return PDU_ID_END_OF_DATA
}

func (pdu *PDUEndOfData) Write(wr io.Writer) {
	binary.Write(wr, binary.BigEndian, uint8(pdu.Version))
	binary.Write(wr, binary.BigEndian, uint8(PDU_ID_END_OF_DATA))
	binary.Write(wr, binary.BigEndian, pdu.SessionId)

	if pdu.Version == PROTOCOL_VERSION_0 {
		binary.Write(wr, binary.BigEndian, uint32(12))
		binary.Write(wr, binary.BigEndian, pdu.SerialNumber)
	} else {
		binary.Write(wr, binary.BigEndian, uint32(24))
		binary.Write(wr, binary.BigEndian, pdu.SerialNumber)
		binary.Write(wr, binary.BigEndian, pdu.RefreshInterval)
		binary.Write(wr, binary.BigEndian, pdu.RetryInterval)
		binary.Write(wr, binary.BigEndian, pdu.ExpireInterval)
	}
}

type PDUCacheReset struct {
	Version uint8
}

func (pdu *PDUCacheReset) String() string {
	return fmt.Sprintf("PDU Cache Reset v%d", pdu.Version)
}

func (pdu *PDUCacheReset) Bytes() []byte {
	b := bytes.NewBuffer([]byte{})
	pdu.Write(b)
	return b.Bytes()
}

func (pdu *PDUCacheReset) SetVersion(version uint8) {
	pdu.Version = version
}

func (pdu *PDUCacheReset) GetVersion() uint8 {
	return pdu.Version
}

func (pdu *PDUCacheReset) GetType() uint8 {
	return PDU_ID_CACHE_RESET
}

func (pdu *PDUCacheReset) Write(wr io.Writer) {
	binary.Write(wr, binary.BigEndian, uint8(pdu.Version))
	binary.Write(wr, binary.BigEndian, uint8(PDU_ID_CACHE_RESET))
	binary.Write(wr, binary.BigEndian, uint16(0))
	binary.Write(wr, binary.BigEndian, uint32(8))
}

type PDURouterKey struct {
	Version              uint8
	Flags                uint8
	SubjectKeyIdentifier []byte
	ASN                  uint32
	SubjectPublicKeyInfo []byte
}

func (pdu *PDURouterKey) String() string {
	return "PDU Router Key"
}

func (pdu *PDURouterKey) Bytes() []byte {
	b := bytes.NewBuffer([]byte{})
	pdu.Write(b)
	return b.Bytes()
}

func (pdu *PDURouterKey) SetVersion(version uint8) {
	pdu.Version = version
}

func (pdu *PDURouterKey) GetVersion() uint8 {
	return pdu.Version
}

func (pdu *PDURouterKey) GetType() uint8 {
	return PDU_ID_ROUTER_KEY
}

func (pdu *PDURouterKey) Write(wr io.Writer) {
	if len(pdu.SubjectKeyIdentifier) != 20 {
		return
	}

	binary.Write(wr, binary.BigEndian, uint8(pdu.Version))
	binary.Write(wr, binary.BigEndian, uint8(PDU_ID_ROUTER_KEY))
	binary.Write(wr, binary.BigEndian, uint8(pdu.Flags))
	binary.Write(wr, binary.BigEndian, uint8(0))
	binary.Write(wr, binary.BigEndian, uint32(32+len(pdu.SubjectPublicKeyInfo)))
	wr.Write(pdu.SubjectKeyIdentifier)
	binary.Write(wr, binary.BigEndian, pdu.ASN)
	wr.Write(pdu.SubjectPublicKeyInfo)
}

type PDUErrorReport struct {
	Version   uint8
	ErrorCode uint16
	PDUCopy   []byte
	ErrorMsg  string
}

func (pdu *PDUErrorReport) String() string {
	return fmt.Sprintf("PDU Error report v%d (error code: %d): bytes PDU copy (%d): %s. Message: %s", pdu.Version, pdu.ErrorCode, len(pdu.PDUCopy), hex.EncodeToString(pdu.PDUCopy), pdu.ErrorMsg)
}

func (pdu *PDUErrorReport) Bytes() []byte {
	b := bytes.NewBuffer([]byte{})
	pdu.Write(b)
	return b.Bytes()
}

func (pdu *PDUErrorReport) SetVersion(version uint8) {
	pdu.Version = version
}

func (pdu *PDUErrorReport) GetVersion() uint8 {
	return pdu.Version
}

func (pdu *PDUErrorReport) GetType() uint8 {
	return PDU_ID_ERROR_REPORT
}

func (pdu *PDUErrorReport) Write(wr io.Writer) {
	nonnull := (pdu.ErrorMsg != "")
	addlen := 0
	if nonnull {
		addlen = 1
	}

	binary.Write(wr, binary.BigEndian, uint8(pdu.Version))
	binary.Write(wr, binary.BigEndian, uint8(PDU_ID_ERROR_REPORT))
	binary.Write(wr, binary.BigEndian, pdu.ErrorCode)
	binary.Write(wr, binary.BigEndian, uint32(12+len(pdu.PDUCopy)+4+len(pdu.ErrorMsg)+addlen))
	binary.Write(wr, binary.BigEndian, uint32(len(pdu.PDUCopy)))
	binary.Write(wr, binary.BigEndian, pdu.PDUCopy)
	binary.Write(wr, binary.BigEndian, uint32(len(pdu.ErrorMsg)+addlen))
	if nonnull {
		binary.Write(wr, binary.BigEndian, []byte(pdu.ErrorMsg))
		binary.Write(wr, binary.BigEndian, uint8(0))
		// Some clients require null-terminated strings
	}
}

type PDUASPA struct {
	Version           uint8
	Flags             uint8
	CustomerASNumber  uint32
	ProviderASNumbers []uint32
}

func (pdu *PDUASPA) String() string {
	return fmt.Sprintf("PDU ASPA v%d TODO", pdu.Version) // XXX: TODO
}

func (pdu *PDUASPA) Bytes() []byte {
	b := bytes.NewBuffer([]byte{})
	pdu.Write(b)
	return b.Bytes()
}

func (pdu *PDUASPA) SetVersion(version uint8) {
	pdu.Version = version
}

func (pdu *PDUASPA) GetVersion() uint8 {
	return pdu.Version
}

func (pdu *PDUASPA) GetType() uint8 {
	return PDU_ID_ASPA
}

func (pdu *PDUASPA) Write(wr io.Writer) {
	binary.Write(wr, binary.BigEndian, uint8(pdu.Version))
	binary.Write(wr, binary.BigEndian, uint8(PDU_ID_ASPA))
	binary.Write(wr, binary.BigEndian, uint8(pdu.Flags))
	binary.Write(wr, binary.BigEndian, uint8(0))
	binary.Write(wr, binary.BigEndian, uint32(12 + (len(pdu.ProviderASNumbers)*4)))
	binary.Write(wr, binary.BigEndian, uint32(pdu.CustomerASNumber))

	for _, pasn := range pdu.ProviderASNumbers {
		binary.Write(wr, binary.BigEndian, uint32(pasn))
	}
}

func DecodeBytes(b []byte) (PDU, error) {
	buf := bytes.NewBuffer(b)
	return Decode(buf)
}

func Decode(rdr io.Reader) (PDU, error) {
	if rdr == nil {
		return nil, errors.New("reader for decoding is nil")
	}

	var pver uint8
	var pduType uint8
	var sessionId_or_flags uint16
	var length uint32

	err := binary.Read(rdr, binary.BigEndian, &pver)
	if err != nil {
		return nil, err
	}

	err = binary.Read(rdr, binary.BigEndian, &pduType)
	if err != nil {
		return nil, err
	}

	err = binary.Read(rdr, binary.BigEndian, &sessionId_or_flags)
	if err != nil {
		return nil, err
	}

	err = binary.Read(rdr, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}

	if length < 8 {
		return nil, fmt.Errorf("wrong PDU length: %d < 8", length)
	}
	if length > messageMaxSize {
		return nil, fmt.Errorf("PDU too large: %d > %d", length, messageMaxSize)
	}

	toread := make([]byte, length - 8)

	err = binary.Read(rdr, binary.BigEndian, toread)
	if err != nil {
		return nil, err
	}

	switch pduType {
	case PDU_ID_SERIAL_NOTIFY:
		if len(toread) != 4 {
			return nil, fmt.Errorf("wrong length for Serial Notify PDU: %d != 4", len(toread))
		}

		serial := binary.BigEndian.Uint32(toread)

		return &PDUSerialNotify{
			Version:      pver,
			SessionId:    sessionId_or_flags,
			SerialNumber: serial,
		}, nil
	case PDU_ID_SERIAL_QUERY:
		if len(toread) != 4 {
			return nil, fmt.Errorf("wrong length for Serial Query PDU: %d != 4", len(toread))
		}

		serial := binary.BigEndian.Uint32(toread)

		return &PDUSerialQuery{
			Version:      pver,
			SessionId:    sessionId_or_flags,
			SerialNumber: serial,
		}, nil
	case PDU_ID_RESET_QUERY:
		if len(toread) != 0 {
			return nil, fmt.Errorf("wrong length for Reset Query PDU: %d != 0", len(toread))
		}
		return &PDUResetQuery{
			Version: pver,
		}, nil
	case PDU_ID_CACHE_RESPONSE:
		if len(toread) != 0 {
			return nil, fmt.Errorf("wrong length for Cache Response PDU: %d != 0", len(toread))
		}

		return &PDUCacheResponse{
			Version:   pver,
			SessionId: sessionId_or_flags,
		}, nil
	case PDU_ID_IPV4_PREFIX:
		if length != 20 {
			return nil, fmt.Errorf("wrong length for IPv4 Prefix PDU: %d != 20", length)
		}

		prefixLen := int(toread[1])
		ip := toread[4:8]
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return nil, fmt.Errorf("ip slice length is not 4 or 16: %+v", addr)
		}

		asn := binary.BigEndian.Uint32(toread[8:])

		return &PDUIPv4Prefix{
			Version: pver,
			Flags:   uint8(toread[0]),
			MaxLen:  uint8(toread[2]),
			ASN:     asn,
			Prefix:  netip.PrefixFrom(addr, prefixLen),
		}, nil
	case PDU_ID_IPV6_PREFIX:
		if length != 32 {
			return nil, fmt.Errorf("wrong length for IPv6 Prefix PDU: %d != 32", length)
		}

		prefixLen := int(toread[1])
		ip := toread[4:20]
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return nil, fmt.Errorf("ip slice length is not 4 or 16: %+v", addr)
		}

		asn := binary.BigEndian.Uint32(toread[20:])

		return &PDUIPv6Prefix{
			Version: pver,
			Flags:   uint8(toread[0]),
			MaxLen:  uint8(toread[2]),
			ASN:     asn,
			Prefix:  netip.PrefixFrom(addr, prefixLen),
		}, nil
	case PDU_ID_END_OF_DATA:
		if length != 12 && length != 24 {
			return nil, fmt.Errorf("wrong length for End of Data PDU: %d != 12 or != 24", length)
		}

		var serial uint32
		var refreshInterval uint32
		var retryInterval uint32
		var expireInterval uint32

		if len(toread) == 4 {
			serial = binary.BigEndian.Uint32(toread)
		} else if len(toread) == 16 {
			serial = binary.BigEndian.Uint32(toread[0:4])
			refreshInterval = binary.BigEndian.Uint32(toread[4:8])
			retryInterval = binary.BigEndian.Uint32(toread[8:12])
			expireInterval = binary.BigEndian.Uint32(toread[12:16])
		}

		return &PDUEndOfData{
			Version:         pver,
			SessionId:       sessionId_or_flags,
			SerialNumber:    serial,
			RefreshInterval: refreshInterval,
			RetryInterval:   retryInterval,
			ExpireInterval:  expireInterval,
		}, nil
	case PDU_ID_CACHE_RESET:
		if length != 8 {
			return nil, fmt.Errorf("wrong length for Cache Reset PDU: %d != 8", length)
		}

		return &PDUCacheReset{
			Version: pver,
		}, nil
	case PDU_ID_ROUTER_KEY:
		if length < 28 {
			return nil, fmt.Errorf("wrong length for Router Key PDU: %d < 28", length)
		}

		asn := binary.BigEndian.Uint32(toread[20:24])
		spki := toread[24:]
		ski := make([]byte, 20)
		copy(ski[:], toread[0:20])

		return &PDURouterKey{
			Version:              pver,
			SubjectKeyIdentifier: ski,
			// Flags is in a spot that is also used by the SessionID, So we we will just bitshift
			Flags:                uint8(sessionId_or_flags >> 8),
			ASN:                  asn,
			SubjectPublicKeyInfo: spki,
		}, nil
	case PDU_ID_ERROR_REPORT:
		if length < 24 {
			return nil, fmt.Errorf("wrong length for Error Report PDU: %d < 24", length)
		}

		lenPdu := binary.BigEndian.Uint32(toread[0:4])
		if len(toread) < int(lenPdu) + 8 {
			return nil, fmt.Errorf("wrong length for Error Report PDU: %d < %d", len(toread), lenPdu + 4)
		}

		errPdu := toread[4 : lenPdu+4]
		lenErrText := binary.BigEndian.Uint32(toread[lenPdu+4 : lenPdu+8])

		// int casting for each value is needed here to prevent an uint32 overflow that could result in
		// upper bound being lower than lower bound causing a crash
		if len(toread) < int(lenPdu)+8+int(lenErrText) {
			return nil, fmt.Errorf("wrong length for Error Report PDU: %d < %d", len(toread), lenPdu + 8 + lenErrText)
		}
		errMsg := string(toread[lenPdu+8 : lenPdu+8+lenErrText])

		return &PDUErrorReport{
			Version:   pver,
			ErrorCode: sessionId_or_flags,
			PDUCopy:   errPdu,
			ErrorMsg:  errMsg,
		}, nil
	case PDU_ID_ASPA:
		if length < 12 {
			return nil, fmt.Errorf("wrong length for ASPA PDU: %d < 12", length)
		}

		CASN := binary.BigEndian.Uint32(toread[0:4])

		PASNs := make([]uint32, 0)
		rbuf := bytes.NewReader(toread[4:])
		var prev_asn uint32
		var asn uint32
		for i := 0; i < int((length - 12) / 4); i++ {
			if i == 0 {
				prev_asn = asn
			}
			err := binary.Read(rbuf, binary.BigEndian, &asn)
			if err != nil {
				return nil, err
			}
			PASNs = append(PASNs, asn)
			if i > 0 {
				if !(asn > prev_asn) {
					return nil, fmt.Errorf("Sorting issue in ASPA Providers: %d > %d", asn, prev_asn)
				}
				prev_asn = asn
			}
		}

		return &PDUASPA{
			Version:           pver,
			// Flags is in a spot that is also used by the SessionID, So we we will just bitshift
			Flags:             uint8(sessionId_or_flags >> 8),
			CustomerASNumber:  CASN,
			ProviderASNumbers: PASNs,
		}, nil
	default:
		return nil, errors.New("could not decode packet")
	}
}
