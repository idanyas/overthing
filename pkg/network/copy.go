package network

import (
	"io"
	"net"
	"sync"
)

// 1KB Buffer: Optimized for Latency (Ping-Pong), not Throughput.
// Prevents receive coalescing and forces immediate flushes.
const copyBufSize = 1024

var bufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, copyBufSize)
		return &buf
	},
}

type closeWriter interface {
	CloseWrite() error
}

func CopyBidirectional(conn1, conn2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Manual copy loop to allow hook injection (QuickAck)
	copyLoop := func(dst, src net.Conn, isTCP bool) {
		defer wg.Done()
		bufPtr := bufPool.Get().(*[]byte)
		defer bufPool.Put(bufPtr)
		buf := *bufPtr

		for {
			// READ
			nr, err := src.Read(buf)
			if nr > 0 {
				// Re-assert QuickAck immediately after reading data
				// This kills the Delayed ACK timer (40ms) on Linux.
				if isTCP {
					ReassertQuickAck(src)
				}

				// WRITE
				nw, ew := dst.Write(buf[0:nr])
				if nw < 0 || nr < nw {
					nw = 0
					if ew == nil {
						ew = io.ErrShortWrite
					}
				}
				if ew != nil {
					break
				}
				if nr != nw {
					break
				}
			}
			if err != nil {
				break
			}
		}

		if cw, ok := dst.(closeWriter); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}

	// Determine which side is the raw TCP connection to apply QuickAck logic
	// Note: conn1/conn2 can be Yamux streams or real TCP conns. 
	// ReassertQuickAck safely checks for *net.TCPConn internally.
	_, isTCP1 := conn1.(*net.TCPConn)
	_, isTCP2 := conn2.(*net.TCPConn)

	go copyLoop(conn1, conn2, isTCP2)
	go copyLoop(conn2, conn1, isTCP1)

	wg.Wait()
}
