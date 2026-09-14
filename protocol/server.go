package protocol

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/xtls/reality"
	"golang.org/x/net/http2"
)

type ServerConfig struct {
	Addr        string
	Dest        string
	Name        string
	Password    string
	DialTimeout time.Duration
	Logger      *slog.Logger
}

type Server struct {
	cfg       ServerConfig
	keys      realityKeys
	log       *slog.Logger
	http      *http.Server
	h3        *http3.Server
	handler   http.Handler
	dialer    net.Dialer
	inner     net.Listener
	innerCert tls.Certificate
	altSvc    string
	token     string
}

func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Password == "" {
		return nil, fmt.Errorf("protocol: password is required")
	}
	if cfg.Dest == "" {
		return nil, fmt.Errorf("protocol: dest is required")
	}
	if cfg.Addr == "" {
		cfg.Addr = ":443"
	}
	host, port, err := splitHostPort(cfg.Dest)
	if err != nil {
		return nil, fmt.Errorf("protocol: dest: %w", err)
	}
	cfg.Dest = joinHostPort(host, port)
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	keys, err := deriveKeys(cfg.Password)
	if err != nil {
		return nil, err
	}
	cn := cfg.Name
	if cn == "" {
		cn = host
	}
	cert, err := newSelfCert(cn)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:       cfg,
		keys:      keys,
		log:       log,
		innerCert: cert,
		altSvc:    altSvc(listenPort(cfg.Addr)),
		token:     hex.EncodeToString(keys.token[:]),
		dialer: net.Dialer{
			Timeout:   cfg.DialTimeout,
			KeepAlive: 30 * time.Second,
		},
	}
	s.handler = http.HandlerFunc(s.serveHTTP)
	return s, nil
}

func (s *Server) realityConfig() *reality.Config {
	host, _, _ := splitHostPort(s.cfg.Dest)
	name := s.cfg.Name
	if name == "" {
		name = host
	}
	return &reality.Config{
		DialContext: s.dialer.DialContext,
		Type:        "tcp",
		Dest:        s.cfg.Dest,
		ServerNames: map[string]bool{name: true, host: true},
		PrivateKey:  s.keys.private,
		ShortIds:    map[[8]byte]bool{s.keys.shortID: true},
		NextProtos:  []string{"h2", "http/1.1"},
	}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	inner, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}
	s.inner = inner
	ln := reality.NewListener(inner, s.realityConfig())

	base := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	s.http = base
	h2s := &http2.Server{}

	port := listenPort(s.cfg.Addr)
	h3tls := &tls.Config{
		Certificates: []tls.Certificate{s.innerCert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{http3.NextProtoH3},
	}
	s.h3 = &http3.Server{
		Addr:      s.cfg.Addr,
		Port:      port,
		Handler:   s.handler,
		TLSConfig: h3tls,
		QUICConfig: &quic.Config{
			KeepAlivePeriod: 15 * time.Second,
			MaxIdleTimeout:  30 * time.Second,
		},
	}

	errCh := make(chan error, 2)
	go func() {
		s.log.Info("listening tcp", "addr", s.cfg.Addr, "dest", s.cfg.Dest)
		for {
			c, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					errCh <- nil
					return
				}
				errCh <- err
				return
			}
			go s.serveTCP(ctx, c, h2s, base)
		}
	}()
	go func() {
		s.log.Info("listening udp/http3", "addr", s.cfg.Addr)
		err := s.h3.ListenAndServe()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			errCh <- fmt.Errorf("http/3: %w", err)
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		_ = inner.Close()
		if s.h3 != nil {
			_ = s.h3.Close()
		}
		<-errCh
		return ctx.Err()
	case err := <-errCh:
		_ = inner.Close()
		if s.h3 != nil {
			_ = s.h3.Close()
		}
		return err
	}
}

func (s *Server) serveTCP(ctx context.Context, c net.Conn, h2s *http2.Server, base *http.Server) {
	proto := "http/1.1"
	if rc, ok := c.(*reality.Conn); ok {
		if p := rc.ConnectionState().NegotiatedProtocol; p != "" {
			proto = p
		}
	}
	if proto == "h2" {
		h2s.ServeConn(c, &http2.ServeConnOpts{
			Context:    ctx,
			BaseConfig: base,
			Handler:    s.handler,
		})
		return
	}
	_ = http.Serve(&onceListener{conn: c}, s.handler)
}

func (s *Server) Close() error {
	var err error
	if s.http != nil {
		err = s.http.Close()
	}
	if s.h3 != nil {
		if e := s.h3.Close(); e != nil && err == nil {
			err = e
		}
	}
	if s.inner != nil {
		if e := s.inner.Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor < 3 {
		w.Header().Set("Alt-Svc", s.altSvc)
	}
	w.Header().Set("Server", "Caddy")
	if r.ProtoMajor >= 3 && r.Method == http.MethodConnect {
		if !s.h3Auth(r) {
			http.Error(w, "404 Not Found\n", http.StatusNotFound)
			return
		}
	}
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	http.Error(w, "404 Not Found\n", http.StatusNotFound)
}

func (s *Server) h3Auth(r *http.Request) bool {
	want := "Bearer " + s.token
	return r.Header.Get("Authorization") == want
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	dest := r.Host
	if dest == "" {
		dest = r.URL.Host
	}
	if err := requireHostPort(dest); err != nil {
		s.log.Debug("rejected connect", "dest", dest, "err", err)
		http.NotFound(w, r)
		return
	}
	up, err := s.dialer.DialContext(r.Context(), "tcp", dest)
	if err != nil {
		s.log.Debug("dial dest failed", "dest", dest, "err", err)
		http.NotFound(w, r)
		return
	}
	defer up.Close()

	if r.ProtoMajor < 2 {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.NotFound(w, r)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err := buf.WriteString("HTTP/1.1 200 Connection Established\r\nServer: Caddy\r\n\r\n"); err != nil {
			return
		}
		if err := buf.Flush(); err != nil {
			return
		}
		var raw net.Conn = conn
		if n := buf.Reader.Buffered(); n > 0 {
			prefix := make([]byte, n)
			_, _ = buf.Read(prefix)
			raw = &prefixConn{Conn: conn, prefix: prefix}
		}
		tun, err := serverTunnel(raw, s.innerCert)
		if err != nil {
			return
		}
		relay(tun, up)
		return
	}

	_ = http.NewResponseController(w).EnableFullDuplex()
	w.WriteHeader(http.StatusOK)
	_ = http.NewResponseController(w).Flush()
	raw := newConn(r.Body, &flushWriter{w: w}, staticAddr{"tcp", r.RemoteAddr}, staticAddr{"tcp", dest})
	tun, err := serverTunnel(raw, s.innerCert)
	if err != nil {
		return
	}
	relay(tun, up)
}

func altSvc(port int) string {
	return `h3=":` + fmt.Sprintf("%d", port) + `"; ma=2592000`
}

type onceListener struct {
	conn net.Conn
	once sync.Once
}

func (l *onceListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c == nil {
		return nil, net.ErrClosed
	}
	return c, nil
}

func (l *onceListener) Close() error {
	if l.conn != nil {
		return l.conn.Close()
	}
	return nil
}

func (l *onceListener) Addr() net.Addr {
	if l.conn != nil {
		return l.conn.LocalAddr()
	}
	return &net.TCPAddr{}
}

var copyBufPool = sync.Pool{
	New: func() any { return make([]byte, 32*1024) },
}

func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		copyAndCloseWrite(a, b)
	}()
	go func() {
		defer wg.Done()
		copyAndCloseWrite(b, a)
	}()
	wg.Wait()
}

func copyAndCloseWrite(dst, src net.Conn) {
	buf := copyBufPool.Get().([]byte)
	defer copyBufPool.Put(buf)
	_, _ = io.CopyBuffer(dst, src, buf)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

type flushWriter struct {
	w http.ResponseWriter
}

func (f *flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if n > 0 {
		_ = http.NewResponseController(f.w).Flush()
	}
	return n, err
}

func (f *flushWriter) Close() error { return nil }
