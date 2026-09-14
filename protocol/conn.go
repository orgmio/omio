package protocol

import (
	"io"
	"net"
	"sync"
	"time"
)

// Conn is a bidirectional tunnel over an HTTP CONNECT stream.
type Conn struct {
	r io.ReadCloser
	w io.WriteCloser

	local  net.Addr
	remote net.Addr

	closeOnce sync.Once
	closeErr  error
}

type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func newConn(r io.ReadCloser, w io.WriteCloser, local, remote net.Addr) *Conn {
	return &Conn{r: r, w: w, local: local, remote: remote}
}

func (c *Conn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *Conn) Write(p []byte) (int, error) { return c.w.Write(p) }

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		err1 := c.w.Close()
		err2 := c.r.Close()
		if err1 != nil {
			c.closeErr = err1
			return
		}
		c.closeErr = err2
	})
	return c.closeErr
}

func (c *Conn) LocalAddr() net.Addr  { return c.local }
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

func (c *Conn) SetDeadline(t time.Time) error {
	err1 := c.SetReadDeadline(t)
	err2 := c.SetWriteDeadline(t)
	if err1 != nil {
		return err1
	}
	return err2
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	if d, ok := c.r.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	if d, ok := c.w.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return d.SetWriteDeadline(t)
	}
	return nil
}

type staticAddr struct {
	net, addr string
}

func (a staticAddr) Network() string { return a.net }
func (a staticAddr) String() string  { return a.addr }
