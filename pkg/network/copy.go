package network

import (
	"io"
	"net"
	"sync"
)

// 32KB Buffer: Standard for high-performance TCP.
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

func CopyBidirectional(conn1, conn2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyLoop := func(dst, src net.Conn) {
		defer wg.Done()
		bufPtr := bufPool.Get().(*[]byte)
		defer bufPool.Put(bufPtr)
		buf := *bufPtr

		for {
			nr, err := src.Read(buf)
			if nr > 0 {
				nw, ew := dst.Write(buf[0:nr])
				if nw < 0 || nw < nr {
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

	go copyLoop(conn1, conn2)
	go copyLoop(conn2, conn1)

	wg.Wait()
}
