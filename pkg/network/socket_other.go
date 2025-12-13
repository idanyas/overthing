//go:build !linux

package network

import "net"

func optimizeTCPPlatform(conn *net.TCPConn) {}

func EnableTCPFastOpen(listener *net.TCPListener) {}

func ReassertQuickAck(conn net.Conn) {}
