package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
)

// MaxMessageSize limits payload size to 4MB to prevent DoS
const MaxMessageSize = 4 * 1024 * 1024

var (
	headerPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 12)
			return &b
		},
	}

	smallMsgPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 128)
			return &b
		},
	}
	
	// Pool for larger messages to prevent allocation spikes/DoS
	largeMsgPool = sync.Pool{
		New: func() interface{} {
			// Allocate max size. We slice it down on usage.
			b := make([]byte, MaxMessageSize)
			return &b
		},
	}
)

type Invitation struct {
	From         []byte
	Key          []byte
	Address      []byte
	Port         uint16
	ServerSocket bool
}

func WriteMessage(w io.Writer, msgType int32, payload []byte) error {
	totalLen := 12 + len(payload)

	if totalLen <= 128 {
		bufPtr := smallMsgPool.Get().(*[]byte)
		buf := (*bufPtr)[:totalLen]
		defer smallMsgPool.Put(bufPtr)

		binary.BigEndian.PutUint32(buf[0:4], RelayMagic)
		binary.BigEndian.PutUint32(buf[4:8], uint32(msgType))
		binary.BigEndian.PutUint32(buf[8:12], uint32(len(payload)))
		if len(payload) > 0 {
			copy(buf[12:], payload)
		}

		_, err := w.Write(buf)
		return err
	}

	if nc, ok := w.(net.Conn); ok {
		headerPtr := headerPool.Get().(*[]byte)
		header := *headerPtr
		defer headerPool.Put(headerPtr)

		binary.BigEndian.PutUint32(header[0:4], RelayMagic)
		binary.BigEndian.PutUint32(header[4:8], uint32(msgType))
		binary.BigEndian.PutUint32(header[8:12], uint32(len(payload)))

		buffers := net.Buffers{header}
		if len(payload) > 0 {
			buffers = append(buffers, payload)
		}

		_, err := buffers.WriteTo(nc)
		return err
	}

	headerPtr := headerPool.Get().(*[]byte)
	header := *headerPtr
	defer headerPool.Put(headerPtr)

	binary.BigEndian.PutUint32(header[0:4], RelayMagic)
	binary.BigEndian.PutUint32(header[4:8], uint32(msgType))
	binary.BigEndian.PutUint32(header[8:12], uint32(len(payload)))

	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
}

func ReadMessage(r io.Reader) (int32, []byte, error) {
	headerPtr := headerPool.Get().(*[]byte)
	header := *headerPtr
	defer headerPool.Put(headerPtr)

	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}

	magic := binary.BigEndian.Uint32(header[0:4])
	if magic != RelayMagic {
		return 0, nil, fmt.Errorf("invalid magic: 0x%08X", magic)
	}

	msgType := int32(binary.BigEndian.Uint32(header[4:8]))
	length := binary.BigEndian.Uint32(header[8:12])

	if length > MaxMessageSize {
		return 0, nil, fmt.Errorf("message too large: %d bytes", length)
	}

	var body []byte
	if length > 0 {
		if length <= 128 {
			bufPtr := smallMsgPool.Get().(*[]byte)
			body = (*bufPtr)[:length]
			if _, err := io.ReadFull(r, body); err != nil {
				smallMsgPool.Put(bufPtr)
				return 0, nil, err
			}
			// Copy out so we can return the buffer to pool
			bodyCopy := make([]byte, length)
			copy(bodyCopy, body)
			smallMsgPool.Put(bufPtr)
			body = bodyCopy
		} else {
			// Use pooled large buffer to prevent DoS via allocation
			bufPtr := largeMsgPool.Get().(*[]byte)
			// We must not defer Put here because we might return the slice. 
			// However, returning a slice of a pooled buffer is dangerous if the caller holds it.
			// The contract of ReadMessage is returning a []byte that the caller owns.
			// So we MUST copy if we use a pool, OR we just allocate if we want to give ownership.
			// BUT the issue is "Allocates up to 4MB immediately".
			// If we allocate new memory, we are vulnerable.
			// If we use pool and copy, we effectively double touch, but we don't spike allocation *count* if we are limited by pool.
			// But wait, if we copy, we still allocate `make([]byte, length)` eventually.
			// The only way to avoid the allocation spike is to use the pool for the read, 
			// and then copy to a precisely sized buffer, OR return a buffer that must be released (API change).
			// Since we cannot change API easily, we will Read into pool, then Copy.
			// This prevents "allocating 4MB before reading". We read into existing memory. 
			// If the Read fails (e.g. connection closes after header), we haven't allocated a new 4MB block on heap that needs GC.
			// We just used the pool.
			
			tempBuf := (*bufPtr)[:length]
			if _, err := io.ReadFull(r, tempBuf); err != nil {
				largeMsgPool.Put(bufPtr)
				return 0, nil, err
			}
			
			body = make([]byte, length)
			copy(body, tempBuf)
			largeMsgPool.Put(bufPtr)
		}
	}

	return msgType, body, nil
}

func XDRBytes(b []byte) []byte {
	l := len(b)
	pad := (4 - (l % 4)) % 4
	out := make([]byte, 4+l+pad)
	binary.BigEndian.PutUint32(out[0:4], uint32(l))
	copy(out[4:], b)
	return out
}

func DecodeInvitation(data []byte) (Invitation, error) {
	offset := 0

	readOpaque := func() []byte {
		if offset+4 > len(data) {
			return nil
		}
		l := int(binary.BigEndian.Uint32(data[offset : offset+4]))
		offset += 4
		if offset+l > len(data) {
			return nil
		}
		val := make([]byte, l)
		copy(val, data[offset:offset+l])
		pad := (4 - (l % 4)) % 4
		offset += l + pad
		return val
	}

	from := readOpaque()
	if from == nil {
		return Invitation{}, fmt.Errorf("malformed invitation: missing 'from'")
	}
	key := readOpaque()
	if key == nil {
		return Invitation{}, fmt.Errorf("malformed invitation: missing 'key'")
	}
	addr := readOpaque()
	if addr == nil {
		return Invitation{}, fmt.Errorf("malformed invitation: missing 'address'")
	}

	var port uint16
	var serverSocket bool

	if offset+4 <= len(data) {
		port = uint16(binary.BigEndian.Uint32(data[offset : offset+4]))
		offset += 4
	}

	if offset+4 <= len(data) {
		serverSocket = binary.BigEndian.Uint32(data[offset:offset+4]) == 1
	}

	return Invitation{
		From:         from,
		Key:          key,
		Address:      addr,
		Port:         port,
		ServerSocket: serverSocket,
	}, nil
}
