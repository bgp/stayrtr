package rtrlib

import (
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

const versionErrorConnections = 200

// rejectVersion opens one connection over net.Pipe, writes query, and checks
// that the cache answers with an Error Report (Unsupported Protocol Version)
// stamped with wantVersion, then closes the connection.
func rejectVersion(setup func(*Client), query []byte, wantVersion uint8) error {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	client := ClientFromConn(serverSide, nil, nil)
	if setup != nil {
		setup(client)
	}
	done := make(chan struct{})
	go func() {
		client.Start()
		close(done)
	}()

	if err := clientSide.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf("setting deadline: %v", err)
	}
	if _, err := clientSide.Write(query); err != nil {
		return fmt.Errorf("writing query: %v", err)
	}

	pdu, err := Decode(clientSide)
	if err != nil {
		return fmt.Errorf("expected an Error Report, got error %v", err)
	}
	report, ok := pdu.(*PDUErrorReport)
	if !ok {
		return fmt.Errorf("expected an Error Report, got %v", pdu)
	}
	if report.ErrorCode != PDU_ERROR_BADPROTOVERSION {
		return fmt.Errorf("expected error code %d, got %d", PDU_ERROR_BADPROTOVERSION, report.ErrorCode)
	}
	if report.Version != wantVersion {
		return fmt.Errorf("expected Error Report version %d, got %d", wantVersion, report.Version)
	}

	if _, err := clientSide.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		return fmt.Errorf("expected the cache to close the connection, got %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("Start did not return after the disconnect")
	}
	return nil
}

func checkVersionRejections(t *testing.T, setup func(*Client), query []byte, wantVersion uint8) {
	failed := 0
	var first error
	for i := 0; i < versionErrorConnections; i++ {
		if err := rejectVersion(setup, query, wantVersion); err != nil {
			failed++
			if first == nil {
				first = fmt.Errorf("connection %d: %v", i, err)
			}
		}
	}
	if failed > 0 {
		t.Errorf("Error Report lost on %d of %d connections; first failure: %v", failed, versionErrorConnections, first)
	}
}

// A router opening with a protocol version the cache does not support must
// receive an Error Report before the cache closes the connection, carrying the
// highest version the cache supports (RFC 8210 Section 7).
func TestUnsupportedVersionErrorReportReachesClient(t *testing.T) {
	resetQueryV2 := []byte{2, PDU_ID_RESET_QUERY, 0, 0, 0, 0, 0, 8}
	checkVersionRejections(t, nil, resetQueryV2, PROTOCOL_VERSION_1)
}

// The enforceVersion path in readLoop rejects a PDU that is not valid at the
// version the cache enforces, here a Router Key at version 0.
func TestEnforcedVersionErrorReportReachesClient(t *testing.T) {
	routerKey := &PDURouterKey{
		Version:              PROTOCOL_VERSION_0,
		SubjectKeyIdentifier: make([]byte, 20),
		ASN:                  64496,
		SubjectPublicKeyInfo: make([]byte, 91),
	}
	setup := func(c *Client) {
		c.SetVersion(PROTOCOL_VERSION_0)
		c.SetDisableVersionCheck(true)
		c.enforceVersion = true
	}
	checkVersionRejections(t, setup, routerKey.Bytes(), PROTOCOL_VERSION_0)
}
