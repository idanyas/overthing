package network

import (
	"io"
	"net"
	"sync"
)

const copyBufSize = 32 * 1024

var bufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, copyBufSize)
		return &buf
	},
}

type closeWriter interface {
	CloseWrite() error
}

// CopyBidirectional copies data between two connections using half-closing
// if supported, allowing for clean shutdowns of protocol streams.
func CopyBidirectional(conn1, conn2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copy := func(dst, src net.Conn) {
		defer wg.Done()
		bufPtr := bufPool.Get().(*[]byte)
		defer bufPool.Put(bufPtr)
		
		io.CopyBuffer(dst, src, *bufPtr)
		
		// Attempt to close the write side of the destination
		if cw, ok := dst.(closeWriter); ok {
			cw.CloseWrite()
		} else {
			// Fallback: close the connection if half-close not supported
			// This might break some protocols but is required for others (like TLS)
			dst.Close()
		}
	}

	go copy(conn1, conn2)
	go copy(conn2, conn1)

	wg.Wait()
}
