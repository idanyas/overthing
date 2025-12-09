package network

import (
	"net"
	"time"
)

func OptimizeConn(conn net.Conn) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}

	tcpConn.SetNoDelay(true)
	tcpConn.SetKeepAlive(true)
	tcpConn.SetKeepAlivePeriod(30 * time.Second)
	optimizeTCPPlatform(tcpConn)
}
