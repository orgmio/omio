package protocol

import (
	"crypto/tls"
	"io"
	"net"
)

const (
	modeNaked    byte = 0
	modeInnerTLS byte = 1
)

func nakedDest(dest string) bool {
	_, port, err := splitHostPort(dest)
	if err != nil {
		return false
	}
	return port == "443" || port == "8443"
}

func clientTunnel(raw net.Conn, dest string) (net.Conn, error) {
	mode := modeInnerTLS
	if nakedDest(dest) {
		mode = modeNaked
	}
	if _, err := raw.Write([]byte{mode}); err != nil {
		return nil, err
	}
	padded := newPaddedConn(raw)
	if mode == modeNaked {
		return padded, nil
	}
	tlsConn := tls.Client(padded, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"mio"},
	})
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

func serverTunnel(raw net.Conn, cert tls.Certificate) (net.Conn, error) {
	var mode [1]byte
	if _, err := io.ReadFull(raw, mode[:]); err != nil {
		return nil, err
	}
	padded := newPaddedConn(raw)
	if mode[0] == modeNaked {
		return padded, nil
	}
	tlsConn := tls.Server(padded, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"mio"},
	})
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	return tlsConn, nil
}
