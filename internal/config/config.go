package config

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/pelletier/go-toml/v2"

	"github.com/orgmio/mio/protocol"
)

// File is client.toml or server.toml for `mio run -c`.
type File struct {
	SOCKS5 *SOCKS5 `toml:"socks5"`
	Peer   *Peer   `toml:"peer"`
	Server *Server `toml:"server"`
}

type SOCKS5 struct {
	Listen string `toml:"listen"`
	Port   int    `toml:"port"`
}

type Peer struct {
	Remote   string `toml:"remote"`
	Port     int    `toml:"port"`
	Dest     string `toml:"dest"`
	DestPort int    `toml:"dest_port"`
	Password string `toml:"password"`
}

type Server struct {
	Listen   string `toml:"listen"`
	Port     int    `toml:"port"`
	Dest     string `toml:"dest"`
	DestPort int    `toml:"dest_port"`
	Password string `toml:"password"`
}

type Role int

const (
	RoleUnknown Role = iota
	RoleClient
	RoleServer
)

func (f File) Role() (Role, error) {
	switch {
	case f.Peer != nil && f.Server != nil:
		return RoleUnknown, fmt.Errorf("config: client.toml has [peer], server.toml has [server], not both")
	case f.Peer != nil:
		return RoleClient, nil
	case f.Server != nil:
		return RoleServer, nil
	default:
		return RoleUnknown, fmt.Errorf("config: need [peer] (client) or [server] (server)")
	}
}

func Load(path string) (File, error) {
	var v File
	b, err := os.ReadFile(path)
	if err != nil {
		return v, fmt.Errorf("config: read %s: %w", path, err)
	}
	if err := toml.Unmarshal(b, &v); err != nil {
		return v, fmt.Errorf("config: parse %s: %w", path, err)
	}
	return v, nil
}

func (f File) ClientConfig() (protocol.ClientConfig, error) {
	if f.Peer == nil {
		return protocol.ClientConfig{}, fmt.Errorf("config: missing [peer]")
	}
	p := f.Peer
	if p.Remote == "" {
		return protocol.ClientConfig{}, fmt.Errorf("config: peer.remote is required")
	}
	if p.Dest == "" {
		return protocol.ClientConfig{}, fmt.Errorf("config: peer.dest is required")
	}
	if p.Password == "" {
		return protocol.ClientConfig{}, fmt.Errorf("config: peer.password is required")
	}
	return protocol.ClientConfig{
		Address:  hostPort(p.Remote, p.Port, 443),
		SNI:      p.Dest,
		Password: p.Password,
	}, nil
}

func (f File) ServerConfig() (protocol.ServerConfig, error) {
	if f.Server == nil {
		return protocol.ServerConfig{}, fmt.Errorf("config: missing [server]")
	}
	s := f.Server
	if s.Dest == "" {
		return protocol.ServerConfig{}, fmt.Errorf("config: server.dest is required")
	}
	if s.Password == "" {
		return protocol.ServerConfig{}, fmt.Errorf("config: server.password is required")
	}
	listen := "0.0.0.0"
	if s.Listen != "" {
		listen = s.Listen
	}
	return protocol.ServerConfig{
		Addr:     hostPort(listen, s.Port, 443),
		Dest:     hostPort(s.Dest, s.DestPort, 443),
		Name:     s.Dest,
		Password: s.Password,
	}, nil
}

func (f File) SOCKS5Listen() string {
	listen := "127.0.0.1"
	port := 1080
	if f.SOCKS5 != nil {
		if f.SOCKS5.Listen != "" {
			listen = f.SOCKS5.Listen
		}
		if f.SOCKS5.Port > 0 {
			port = f.SOCKS5.Port
		}
	}
	return hostPort(listen, port, 1080)
}

func hostPort(host string, port, def int) string {
	if port <= 0 {
		port = def
	}
	if host == "" {
		host = "0.0.0.0"
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}
