//go:build !linux
// +build !linux

package transport

import (
	"syscall"
)

func setTCPOptions(network, address string, c syscall.RawConn) error {
	// Non-Linux platforms - best effort TCP options
	return c.Control(func(fd uintptr) {
		// Most platforms support TCP_NODELAY
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)

		// Set socket buffer sizes if supported
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4*1024*1024)
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4*1024*1024)

		// Enable SO_KEEPALIVE
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
	})
}
