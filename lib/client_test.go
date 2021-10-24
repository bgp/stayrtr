package rtrlib

import (
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
	Data prefixfile.VRPList

	InitSerial bool
	Serial     uint32
	SessionID  uint16
}

func getClientConguration() ClientConfiguration {
	return ClientConfiguration{
		ProtocolVersion: 1,
		RefreshInterval: 10,
		RetryInterval:   15,
		ExpireInterval:  20,
	}
}
func getClient() *TestClient {
	return &TestClient{
		Data: prefixfile.VRPList{
			Metadata: prefixfile.MetaData{},
			Data:     make([]prefixfile.VRPJson, 0),
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
	cs := NewClientSession(getClientConguration(), getClient())
	cs.SendResetQuery()
	c := <-cs.transmits

	reset := &PDUResetQuery{PROTOCOL_VERSION_1}

	if !cmp.Equal(c, reset) {
		t.Errorf("Wanted a PDU Reset Query, but got (%+v)", c)
	}
}
