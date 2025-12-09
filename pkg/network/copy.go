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

// CopyBidirectional copies data between two connections and closes them
// when the copy finishes or errors. This prevents deadlocks.
func CopyBidirectional(conn1, conn2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copy := func(dst, src net.Conn) {
		defer wg.Done()
		bufPtr := bufPool.Get().(*[]byte)
		defer bufPool.Put(bufPtr)
		
		io.CopyBuffer(dst, src, *bufPtr)
		
		// Aggressively close both on first error/EOF to unblock the other side
		conn1.Close()
		conn2.Close()
	}

	go copy(conn1, conn2)
	go copy(conn2, conn1)

	wg.Wait()
}
