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

	// Disable Nagle's algorithm for lower latency
	tcpConn.SetNoDelay(true)
	
	// Enable KeepAlive to detect dead connections
	tcpConn.SetKeepAlive(true)
	tcpConn.SetKeepAlivePeriod(30 * time.Second)
	
	// We do NOT set Read/Write buffers manually, letting Linux auto-tune 
	// (tcp_moderate_rcvbuf) is generally superior for mixed workloads.
	
	optimizeTCPPlatform(tcpConn)
}
