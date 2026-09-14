package inbound

import (
	"context"
	"log"
	"net"

	"github.com/things-go/go-socks5"
)

// SOCKS5 is a SOCKS5 inbound that dials through a mio client.
type SOCKS5 struct {
	srv *socks5.Server
}

// NewSOCKS5 builds a SOCKS5 server. Only CONNECT is allowed.
func NewSOCKS5(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *SOCKS5 {
	return &SOCKS5{
		srv: socks5.NewServer(
			socks5.WithDial(dial),
			socks5.WithRule(&socks5.PermitCommand{EnableConnect: true}),
			socks5.WithLogger(socks5.NewLogger(log.Default())),
		),
	}
}

func (s *SOCKS5) Serve(l net.Listener) error {
	return s.srv.Serve(l)
}
