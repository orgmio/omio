package protocol

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func splitHostPort(addr string) (string, string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		return host, port, nil
	}
	if strings.Count(addr, ":") == 0 && addr != "" {
		return addr, "443", nil
	}
	return "", "", err
}

func joinHostPort(host, port string) string {
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(host, port)
}

func listenPort(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 443
	}
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 {
		return 443
	}
	return n
}

func requireHostPort(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("destination must be host:port: %w", err)
	}
	if host == "" || port == "" {
		return fmt.Errorf("invalid destination %q", addr)
	}
	return nil
}
