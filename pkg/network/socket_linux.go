//go:build linux

package network

import (
	"net"
	"syscall"

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

// ReassertQuickAck sets TCP_QUICKACK again. This is needed because Linux
// resets this flag after every recv() syscall.
func ReassertQuickAck(conn net.Conn) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return
	}
	rawConn.Control(func(fd uintptr) {
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_QUICKACK, 1)
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
