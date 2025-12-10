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
		}
		// NOTE: We do NOT fallback to Close() here. 
		// If the connection doesn't support CloseWrite (like Yamux), 
		// calling Close() would tear down the whole stream, causing data loss 
		// on the other direction. We rely on the caller to close the connections
		// when CopyBidirectional returns.
	}

	go copy(conn1, conn2)
	go copy(conn2, conn1)

	wg.Wait()
}
