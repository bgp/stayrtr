package rtrlib

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/bgp/stayrtr/prefixfile"
	"github.com/google/go-cmp/cmp"
)

var (
	Serial     = uint32(0)
	Session    = uint16(0)
	InitSerial = false
)

type TestClient struct {
	Data prefixfile.RPKIList

	InitSerial bool
	Serial     uint32
	SessionID  uint16
}

func getBasicClientConguration(version int) ClientConfiguration {
	return ClientConfiguration{
		ProtocolVersion: uint8(version),
		RefreshInterval: 10,
		RetryInterval:   15,
		ExpireInterval:  20,
	}
}

func getClient() *TestClient {
	return &TestClient{
		Data: prefixfile.RPKIList{
			Metadata: prefixfile.MetaData{},
			ROA:      make([]prefixfile.VRPJson, 0),
		},
		InitSerial: InitSerial,
		Serial:     Serial,
		SessionID:  Session,
	}
}

func (tc *TestClient) HandlePDU(cs *ClientSession, pdu PDU) {}

func (tc *TestClient) ClientConnected(cs *ClientSession) {}

func (tc *TestClient) ClientDisconnected(cs *ClientSession) {}

func TestSendResetQuery(t *testing.T) {
	tests := []struct {
		desc    string
		version int
		want    PDU
	}{{
		desc: "Reset Query, Version 0",
		want: &PDUResetQuery{PROTOCOL_VERSION_0},
	}, {
		desc:    "Reset Query, Version 1",
		version: 1,
		want:    &PDUResetQuery{PROTOCOL_VERSION_1},
	}, {
		desc:    "Reset Query, Version 2",
		version: 2,
		want:    &PDUResetQuery{PROTOCOL_VERSION_2},
	}}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			cs := NewClientSession(getBasicClientConguration(tc.version), getClient())
			cs.SendResetQuery()
			c := <-cs.transmits

			if !cmp.Equal(c, tc.want) {
				t.Errorf("Wanted (%+v), but got (%+v)", tc.want, c)
			}
		})
	}
}

func TestSendSerialQuery(t *testing.T) {
	tests := []struct {
		desc    string
		version int
		want    PDU
	}{{
		desc:    "Serial Query PDU, Version 1",
		version: 1,
		want:    &PDUSerialQuery{PROTOCOL_VERSION_1, 123, 456},
	}, {
		desc:    "Serial Query PDU, Version 2",
		version: 2,
		want:    &PDUSerialQuery{PROTOCOL_VERSION_2, 123, 456},
	}}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			cs := NewClientSession(getBasicClientConguration(tc.version), getClient())
			cs.SendSerialQuery(123, 456)
			c := <-cs.transmits

			if !cmp.Equal(c, tc.want) {
				t.Errorf("Wanted (%+v), but got (%+v)", tc.want, c)
			}
		})
	}
}

func TestRouterKeyEncodeDecode(t *testing.T) {
	p := &PDURouterKey{
		Version:              1,
		Flags:                1,
		SubjectKeyIdentifier: []byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
		ASN:                  64497,
		SubjectPublicKeyInfo: []byte("This is not a real key"),
	}

	buf := bytes.NewBuffer(nil)
	p.Write(buf)

	outputPdu, err := Decode(buf)

	if err != nil {
		t.FailNow()
	}

	orig := fmt.Sprintf("%#v", p)
	decode := fmt.Sprintf("%#v", outputPdu)
	if orig != decode {
		t.Fatalf("%s\n is not\n%s", orig, decode)
		t.FailNow()
	}
}

func TestASPAEncodeDecode(t *testing.T) {
	p := &PDUASPA{
		Version:           1,
		Flags:             1,
		CustomerASNumber:  64497,
		ProviderASNumbers: []uint32{64498, 64499},
	}

	buf := bytes.NewBuffer(nil)
	p.Write(buf)

	outputPdu, err := Decode(buf)

	if err != nil {
		t.FailNow()
	}

	orig := fmt.Sprintf("%#v", p)
	decode := fmt.Sprintf("%#v", outputPdu)
	if orig != decode {
		t.Fatalf("%s\n is not\n%s", orig, decode)
		t.FailNow()
	}
}
