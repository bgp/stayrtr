//go:build !linux

package rtrlib

import (
	"fmt"
	"net"
	"syscall"
)

func enableTCPMD5(l *net.TCPListener, password string) error {
	return fmt.Errorf("TCP MD5 signature support is only available on Linux")
}

func enableTCPMD5Dial(network, address string, c syscall.RawConn, password string) error {
	return fmt.Errorf("TCP MD5 signature support is only available on Linux")
}
