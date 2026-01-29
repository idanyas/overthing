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
	
	largeMsgPool = sync.Pool{
		New: func() interface{} {
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
		// FIX: No defer here for pool return

		binary.BigEndian.PutUint32(buf[0:4], RelayMagic)
		binary.BigEndian.PutUint32(buf[4:8], uint32(msgType))
		binary.BigEndian.PutUint32(buf[8:12], uint32(len(payload)))
		if len(payload) > 0 {
			copy(buf[12:], payload)
		}

		_, err := w.Write(buf)
		// Explicitly return to pool after use
		smallMsgPool.Put(bufPtr)
		return err
	}

	// For larger messages, use headers and writes
	if nc, ok := w.(net.Conn); ok {
		headerPtr := headerPool.Get().(*[]byte)
		header := *headerPtr
		
		binary.BigEndian.PutUint32(header[0:4], RelayMagic)
		binary.BigEndian.PutUint32(header[4:8], uint32(msgType))
		binary.BigEndian.PutUint32(header[8:12], uint32(len(payload)))

		buffers := net.Buffers{header}
		if len(payload) > 0 {
			buffers = append(buffers, payload)
		}

		_, err := buffers.WriteTo(nc)
		headerPool.Put(headerPtr)
		return err
	}

	headerPtr := headerPool.Get().(*[]byte)
	header := *headerPtr

	binary.BigEndian.PutUint32(header[0:4], RelayMagic)
	binary.BigEndian.PutUint32(header[4:8], uint32(msgType))
	binary.BigEndian.PutUint32(header[8:12], uint32(len(payload)))

	if _, err := w.Write(header); err != nil {
		headerPool.Put(headerPtr)
		return err
	}
	headerPool.Put(headerPtr)
	
	if len(payload) > 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
}

func ReadMessage(r io.Reader) (int32, []byte, error) {
	headerPtr := headerPool.Get().(*[]byte)
	header := *headerPtr

	if _, err := io.ReadFull(r, header); err != nil {
		headerPool.Put(headerPtr)
		return 0, nil, err
	}

	magic := binary.BigEndian.Uint32(header[0:4])
	if magic != RelayMagic {
		headerPool.Put(headerPtr)
		return 0, nil, fmt.Errorf("invalid magic: 0x%08X", magic)
	}

	msgType := int32(binary.BigEndian.Uint32(header[4:8]))
	length := binary.BigEndian.Uint32(header[8:12])
	
	// Done with header buffer
	headerPool.Put(headerPtr)

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
			bodyCopy := make([]byte, length)
			copy(bodyCopy, body)
			smallMsgPool.Put(bufPtr)
			body = bodyCopy
		} else {
			bufPtr := largeMsgPool.Get().(*[]byte)
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
