package rtrlib

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

var (
	Serial     = uint32(0)
	Session    = uint16(0)
	InitSerial = false
)

type TestClient struct {
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
		desc:    "Serial Query PDU",
		version: 1,
		want:    &PDUSerialQuery{PROTOCOL_VERSION_1, 123, 456},
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
