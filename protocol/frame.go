package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
)

const maxFrame = 16 * 1024

type paddedConn struct {
	net.Conn
	readMu  sync.Mutex
	writeMu sync.Mutex
	buf     []byte // decoded bytes left over after a Read
	rbuf    []byte // reused raw frame body buffer
	wbuf    []byte // reused framed write buffer (header + payload + padding)
}

func newPaddedConn(c net.Conn) *paddedConn {
	return &paddedConn{Conn: c}
}

func (c *paddedConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	sent := 0
	for len(p) > 0 {
		n := min(len(p), maxFrame)
		pad := paddingFor(n)
		need := 4 + n + pad
		if cap(c.wbuf) < need {
			c.wbuf = make([]byte, need)
		} else {
			c.wbuf = c.wbuf[:need]
		}
		binary.BigEndian.PutUint16(c.wbuf[0:2], uint16(n))
		binary.BigEndian.PutUint16(c.wbuf[2:4], uint16(pad))
		copy(c.wbuf[4:4+n], p[:n])
		if pad > 0 {
			if _, err := rand.Read(c.wbuf[4+n : need]); err != nil {
				return sent, err
			}
		}
		if _, err := c.Conn.Write(c.wbuf); err != nil {
			return sent, err
		}
		p = p[n:]
		sent += n
	}
	return sent, nil
}

func (c *paddedConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	var hdr [4]byte
	if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
		return 0, err
	}
	size := int(binary.BigEndian.Uint16(hdr[0:2]))
	pad := int(binary.BigEndian.Uint16(hdr[2:4]))
	if size > maxFrame {
		return 0, io.ErrUnexpectedEOF
	}
	need := size + pad
	if cap(c.rbuf) < need {
		c.rbuf = make([]byte, need)
	} else {
		c.rbuf = c.rbuf[:need]
	}
	if _, err := io.ReadFull(c.Conn, c.rbuf[:need]); err != nil {
		return 0, err
	}
	data := c.rbuf[:size]
	n := copy(p, data)
	if n < len(data) {
		c.buf = append(c.buf[:0], data[n:]...)
	}
	return n, nil
}

func paddingFor(n int) int {
	const bucket = 256
	need := n + 16
	padded := ((need + bucket - 1) / bucket) * bucket
	pad := padded - n
	if pad < 16 {
		pad = 16
	}
	if pad > 2048 {
		pad = 16 + n%240
	}
	return pad
}
