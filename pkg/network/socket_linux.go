//go:build linux

package network

import (
	"net"

	"golang.org/x/sys/unix"
)

func optimizeTCPPlatform(conn *net.TCPConn) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return
	}

	rawConn.Control(func(fd uintptr) {
		unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
		unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_QUICKACK, 1)
	})
}

func EnableTCPFastOpen(listener *net.TCPListener) {
	rawConn, err := listener.SyscallConn()
	if err != nil {
		return
	}
	rawConn.Control(func(fd uintptr) {
		unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN, 256)
	})
}
