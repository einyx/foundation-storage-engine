//go:build !linux
// +build !linux

package transport

import (
	"net"
)

// SetAdaptiveTCPOptions is a no-op on non-Linux systems
func SetAdaptiveTCPOptions(conn net.Conn) error {
	// On non-Linux systems, just apply basic TCP settings
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
	}
	return nil
}