package protocol

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

type level int

const (
	levelH1 level = iota
	levelH2
	levelH3
)

type ClientConfig struct {
	Address  string
	SNI      string
	Password string
}

type Client struct {
	keys   realityKeys
	sni    string
	addr   string
	h2     *http2.Transport
	h3     *http3.Transport
	mu     sync.Mutex
	cc     *http2.ClientConn
	level  level
	closed atomic.Bool
}

func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Password == "" {
		return nil, fmt.Errorf("protocol: password is required")
	}
	if cfg.Address == "" {
		return nil, fmt.Errorf("protocol: server address is required")
	}
	host, port, err := splitHostPort(cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("protocol: server address: %w", err)
	}
	addr := joinHostPort(host, port)
	sni := cfg.SNI
	if sni == "" {
		sni = host
	}
	keys, err := deriveKeys(cfg.Password)
	if err != nil {
		return nil, err
	}
	return &Client{
		keys:  keys,
		sni:   sni,
		addr:  addr,
		level: levelH1,
		h2: &http2.Transport{
			DisableCompression: true,
			IdleConnTimeout:    90 * time.Second,
		},
		h3: newH3Transport(addr),
	}, nil
}

func (c *Client) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if c.closed.Load() {
		return nil, net.ErrClosed
	}
	if network != "" && network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("protocol: unsupported network %q", network)
	}
	if err := requireHostPort(address); err != nil {
		return nil, err
	}

	c.mu.Lock()
	lv := c.level
	c.mu.Unlock()

	if lv >= levelH3 {
		conn, err := c.dialH3(ctx, address)
		if err == nil {
			return conn, nil
		}
		c.setLevel(levelH2)
	}
	if lv >= levelH2 {
		conn, err := c.dialH2(ctx, address)
		if err == nil {
			c.tryH3()
			return conn, nil
		}
		c.setLevel(levelH1)
		c.dropConn()
	}
	conn, err := c.dialH1(ctx, address)
	if err != nil {
		return nil, err
	}
	c.tryH2()
	return conn, nil
}

func (c *Client) setLevel(lv level) {
	c.mu.Lock()
	if lv < c.level {
		c.level = lv
	}
	c.mu.Unlock()
}

func (c *Client) bumpLevel(lv level) {
	c.mu.Lock()
	if lv > c.level {
		c.level = lv
	}
	c.mu.Unlock()
}

func (c *Client) dialH1(ctx context.Context, dest string) (net.Conn, error) {
	raw, err := dialReality(ctx, c.addr, c.sni, c.keys, []string{"http/1.1"})
	if err != nil {
		return nil, err
	}
	tun, err := connectHTTP1(raw, dest)
	if err != nil {
		raw.Close()
		return nil, err
	}
	out, err := clientTunnel(tun, dest)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return out, nil
}

func (c *Client) dialH2(ctx context.Context, dest string) (net.Conn, error) {
	pr, pw := io.Pipe()
	u := &url.URL{Scheme: "https", Host: c.addr}
	req := (&http.Request{
		Method:        http.MethodConnect,
		URL:           u,
		Host:          dest,
		Header:        make(http.Header),
		Body:          pr,
		ContentLength: -1,
	}).WithContext(ctx)
	req.Header.Set("User-Agent", "")
	cc, err := c.h2Conn(ctx)
	if err != nil {
		pr.Close()
		pw.Close()
		return nil, err
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		pr.Close()
		pw.Close()
		c.dropConn()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		pr.Close()
		pw.Close()
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("protocol: http/2 connect %s: status %s", dest, resp.Status)
	}
	raw := newConn(resp.Body, pw, staticAddr{"tcp", "mio"}, staticAddr{"tcp", dest})
	return clientTunnel(raw, dest)
}

func (c *Client) dialH3(ctx context.Context, dest string) (net.Conn, error) {
	raw, err := connectHTTP3(ctx, c.h3, c.addr, dest, bearerToken(c.keys.token))
	if err != nil {
		return nil, err
	}
	return clientTunnel(raw, dest)
}

func (c *Client) h2Conn(ctx context.Context) (*http2.ClientConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cc != nil && c.cc.CanTakeNewRequest() {
		return c.cc, nil
	}
	raw, err := dialReality(ctx, c.addr, c.sni, c.keys, []string{"h2", "http/1.1"})
	if err != nil {
		return nil, err
	}
	cc, err := c.h2.NewClientConn(raw)
	if err != nil {
		raw.Close()
		return nil, err
	}
	c.cc = cc
	return cc, nil
}

func (c *Client) tryH2() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		raw, err := dialReality(ctx, c.addr, c.sni, c.keys, []string{"h2", "http/1.1"})
		if err != nil {
			return
		}
		cc, err := c.h2.NewClientConn(raw)
		if err != nil {
			raw.Close()
			return
		}
		c.mu.Lock()
		if c.cc != nil {
			_ = c.cc.Close()
		}
		c.cc = cc
		c.level = levelH2
		c.mu.Unlock()
		c.tryH3()
	}()
}

func (c *Client) tryH3() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+c.addr+"/", nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", "")
		resp, err := c.h3.RoundTrip(req)
		if err != nil {
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		c.bumpLevel(levelH3)
	}()
}

func (c *Client) dropConn() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cc != nil {
		_ = c.cc.Close()
		c.cc = nil
	}
}

func (c *Client) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	c.dropConn()
	c.h2.CloseIdleConnections()
	if c.h3 != nil {
		_ = c.h3.Close()
	}
	return nil
}
