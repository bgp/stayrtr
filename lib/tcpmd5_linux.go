//go:build linux

package rtrlib

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// enableTCPMD5 installs a shared TCP MD5 signature key (RFC 2385) on the
// listener's socket so the kernel enforces it on every accepted connection.
// Peers are matched via the prefix extension (TCP_MD5SIG_EXT, prefixlen 0 =
// wildcard) so a single key covers all IPv4 and IPv6 clients.
//
// l must be a plain TCP listener, not MPTCP: the kernel's MPTCP option
// handling doesn't implement TCP_MD5SIG* at all and fails every call here
// with ENOPROTOOPT, so the caller must disable MultipathTCP before Listen.
func enableTCPMD5(l *net.TCPListener, password string) error {
	if len(password) > unix.TCP_MD5SIG_MAXKEYLEN {
		return fmt.Errorf("TCP MD5 password too long: max %d bytes", unix.TCP_MD5SIG_MAXKEYLEN)
	}

	sc, err := l.SyscallConn()
	if err != nil {
		return err
	}

	var domain int
	var sockErr error
	if ctrlErr := sc.Control(func(fd uintptr) {
		domain, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_DOMAIN)
	}); ctrlErr != nil {
		return ctrlErr
	}
	if sockErr != nil {
		return fmt.Errorf("getsockopt SO_DOMAIN: %w", sockErr)
	}

	// A dual-stack IPv6 listener needs both a plain IPv6 wildcard key and a
	// v4-mapped (::ffff:0:0/0) one: the kernel decides whether an incoming
	// peer is v4 or v6 from the address bytes, not from the socket family.
	sigs := []unix.TCPMD5Sig{buildTCPMD5Sig(uint16(domain), false, password)}
	if domain == unix.AF_INET6 {
		sigs = append(sigs, buildTCPMD5Sig(unix.AF_INET6, true, password))
	}

	for i := range sigs {
		sig := sigs[i]
		if ctrlErr := sc.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptTCPMD5Sig(int(fd), unix.IPPROTO_TCP, unix.TCP_MD5SIG_EXT, &sig)
		}); ctrlErr != nil {
			return ctrlErr
		}
		if sockErr != nil {
			if errors.Is(sockErr, unix.ENOPROTOOPT) {
				return fmt.Errorf("setsockopt TCP_MD5SIG_EXT: %w (the listener may be an MPTCP socket, which doesn't support this option; or the kernel was built without CONFIG_TCP_MD5SIG)", sockErr)
			}
			return fmt.Errorf("setsockopt TCP_MD5SIG_EXT: %w", sockErr)
		}
	}

	return nil
}

// enableTCPMD5Dial installs a TCP MD5 signature key (RFC 2385) scoped to the
// exact peer being dialed, using network ("tcp4" or "tcp6", as resolved by
// net.Dialer) to disambiguate the family. It must run from inside a
// net.Dialer.Control callback, before connect() sends the SYN.
func enableTCPMD5Dial(network, address string, c syscall.RawConn, password string) error {
	if len(password) > unix.TCP_MD5SIG_MAXKEYLEN {
		return fmt.Errorf("TCP MD5 password too long: max %d bytes", unix.TCP_MD5SIG_MAXKEYLEN)
	}

	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("could not parse peer address %q", address)
	}

	var sig unix.TCPMD5Sig
	sig.Keylen = uint16(len(password))
	copy(sig.Key[:], password)

	if ip4 := ip.To4(); ip4 != nil && network != "tcp6" {
		// sockaddr_in: Family(2)=Addr.Family, then Data[0:2]=port, Data[2:6]=addr.
		sig.Addr.Family = unix.AF_INET
		copy(sig.Addr.Data[2:6], ip4)
	} else {
		sig.Addr.Family = unix.AF_INET6
		copy(sig.Addr.Data[6:22], ip.To16())
	}

	var sockErr error
	if ctrlErr := c.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptTCPMD5Sig(int(fd), unix.IPPROTO_TCP, unix.TCP_MD5SIG, &sig)
	}); ctrlErr != nil {
		return ctrlErr
	}
	if sockErr != nil {
		if errors.Is(sockErr, unix.ENOPROTOOPT) {
			return fmt.Errorf("setsockopt TCP_MD5SIG: %w (the socket may be MPTCP, which doesn't support this option; or the kernel was built without CONFIG_TCP_MD5SIG)", sockErr)
		}
		return fmt.Errorf("setsockopt TCP_MD5SIG: %w", sockErr)
	}
	return nil
}

// buildTCPMD5Sig builds a wildcard (prefixlen 0) key for family. v4mapped
// selects the ::ffff:0:0/0 range so IPv4 peers on a dual-stack listener are
// matched by the kernel's AF_INET key path.
func buildTCPMD5Sig(family uint16, v4mapped bool, password string) unix.TCPMD5Sig {
	var sig unix.TCPMD5Sig
	sig.Flags = unix.TCP_MD5SIG_FLAG_PREFIX
	sig.Keylen = uint16(len(password))
	copy(sig.Key[:], password)

	// Addr is a SockaddrStorage (Family uint16 + opaque Data), read by the kernel
	// as a sockaddr_in6 when family is AF_INET6: Data[0:2]=port, Data[2:6]=flowinfo,
	// Data[6:22]=sin6_addr. Bytes 10-11 of that address are the ::ffff: marker.
	sig.Addr.Family = family
	if v4mapped {
		sig.Addr.Data[16] = 0xff
		sig.Addr.Data[17] = 0xff
	}

	return sig
}
