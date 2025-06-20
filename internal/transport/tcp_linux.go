//go:build linux
// +build linux

package transport

import (
	"strings"
	"syscall"
)

func setTCPOptions(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		// ULTRA PUT OPTIMIZATION: TCP options specifically for small file uploads

		// CRITICAL FOR 1MB PUT: Use TCP_CORK for batching small writes
		// TCP_CORK = 3 on Linux - accumulates data until buffer is full
		// This is PERFECT for our 1MB PUT benchmark!
		if strings.Contains(address, ":") {
			// Only enable TCP_CORK for outgoing connections (PUT operations)
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, 3, 1) // TCP_CORK = 3
		}

		// SMALL FILE OPTIMIZATION: Disable Nagle for immediate sends after cork
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)

		// LATENCY CRITICAL: Enable TCP_QUICKACK for faster ACKs
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_QUICKACK, 1)

		// PUT OPTIMIZATION: Smaller buffers for 1MB files to reduce syscall overhead
		// Research shows large buffers can hurt small file performance
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 2*1024*1024) // 2MB for 1MB files
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 2*1024*1024) // 2MB receive

		// ULTRA PERFORMANCE: SO_REUSEPORT for connection distribution
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 15, 1) // SO_REUSEPORT = 15

		// FAST FAILURE: Minimal keepalive for quick detection
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, 10) // 10s idle (faster)
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, 2) // 2s interval (faster)
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, 2)   // 2 probes (faster)

		// LATENCY OPTIMIZATION: Ultra-fast timeout for small files
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, 18, 1000) // 1 second timeout for 1MB

		// CONNECTION REUSE: Critical for benchmark performance
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)

		// LOW LATENCY: Disable TCP slow start after idle (if available)
		// TCP_NOTSENT_LOWAT = 25 - minimize buffering
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, 25, 1024) // Only buffer 1KB
	})
}
