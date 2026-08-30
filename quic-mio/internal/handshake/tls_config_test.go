package handshake

import (
	"crypto/tls"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetupConfigDoesNotClone(t *testing.T) {
	local := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42}
	remote := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}

	orig := &tls.Config{MinVersion: tls.VersionTLS12}
	require.Same(t, orig, setupConfigForServer(orig, local, remote))
	require.Same(t, orig, setupConfigForClient(orig))
}

func TestQUICConfigClientHelloInfoConn(t *testing.T) {
	local := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42}
	remote := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}
	qc := getQUICConfig(&tls.Config{}, local, remote)
	require.NotNil(t, qc.ClientHelloInfoConn)
	require.Equal(t, local, qc.ClientHelloInfoConn.LocalAddr())
	require.Equal(t, remote, qc.ClientHelloInfoConn.RemoteAddr())
	require.True(t, qc.EnableSessionEvents)
}
