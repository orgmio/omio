package protocol

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
)

type chromeTLSConn struct {
	conn  net.Conn
	state tls.ConnectionState
}

func (c chromeTLSConn) Read(p []byte) (int, error)         { return c.conn.Read(p) }
func (c chromeTLSConn) Write(p []byte) (int, error)        { return c.conn.Write(p) }
func (c chromeTLSConn) Close() error                       { return c.conn.Close() }
func (c chromeTLSConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c chromeTLSConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c chromeTLSConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c chromeTLSConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c chromeTLSConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
func (c chromeTLSConn) ConnectionState() tls.ConnectionState {
	return c.state
}

type realityClient struct {
	*utls.UConn
	authKey  []byte
	verified bool
}

func (c *realityClient) tlsState() tls.ConnectionState {
	st := c.UConn.ConnectionState()
	return tls.ConnectionState{
		Version:                     st.Version,
		HandshakeComplete:           st.HandshakeComplete,
		DidResume:                   st.DidResume,
		CipherSuite:                 st.CipherSuite,
		NegotiatedProtocol:          st.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  st.NegotiatedProtocolIsMutual,
		ServerName:                  st.ServerName,
		PeerCertificates:            st.PeerCertificates,
		VerifiedChains:              st.VerifiedChains,
		SignedCertificateTimestamps: st.SignedCertificateTimestamps,
		OCSPResponse:                st.OCSPResponse,
		TLSUnique:                   st.TLSUnique,
	}
}

func (c *realityClient) verifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("reality: no certificate")
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("reality: dest certificate (not authenticated)")
	}
	mac := hmac.New(sha512.New, c.authKey)
	mac.Write(pub)
	if !bytes.Equal(mac.Sum(nil), cert.Signature) {
		return fmt.Errorf("reality: dest certificate (not authenticated)")
	}
	c.verified = true
	return nil
}

func dialReality(ctx context.Context, address, sni string, keys realityKeys, alpn []string) (net.Conn, error) {
	if len(alpn) == 0 {
		alpn = []string{"http/1.1", "h2"}
	}
	d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	rc := &realityClient{}
	ucfg := &utls.Config{
		ServerName:             sni,
		InsecureSkipVerify:     true,
		VerifyPeerCertificate:  rc.verifyPeerCertificate,
		NextProtos:             alpn,
		SessionTicketsDisabled: false,
	}
	uconn := utls.UClient(raw, ucfg, utls.HelloChrome_102)
	rc.UConn = uconn
	if err := uconn.BuildHandshakeState(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("reality: build hello: %w", err)
	}
	hello := uconn.HandshakeState.Hello
	if len(hello.Raw) < 71 {
		raw.Close()
		return nil, fmt.Errorf("reality: client hello too short (%d)", len(hello.Raw))
	}
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)
	hello.SessionId[0], hello.SessionId[1], hello.SessionId[2] = 0, 1, 0
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], keys.shortID[:])

	pub, err := ecdh.X25519().NewPublicKey(keys.public)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("reality: public key: %w", err)
	}
	ks := uconn.HandshakeState.State13.KeyShareKeys
	if ks == nil {
		raw.Close()
		return nil, fmt.Errorf("reality: no TLS 1.3 key share")
	}
	ecdhe := ks.Ecdhe
	if ecdhe == nil {
		ecdhe = ks.MlkemEcdhe
	}
	if ecdhe == nil {
		raw.Close()
		return nil, fmt.Errorf("reality: fingerprint has no X25519 share")
	}
	shared, err := ecdhe.ECDH(pub)
	if err != nil {
		raw.Close()
		return nil, err
	}
	rc.authKey = shared
	if _, err := hkdf.New(sha256.New, rc.authKey, hello.Random[:20], []byte("REALITY")).Read(rc.authKey); err != nil {
		raw.Close()
		return nil, err
	}
	block, err := aes.NewCipher(rc.authKey)
	if err != nil {
		raw.Close()
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		raw.Close()
		return nil, err
	}
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)
	if err := uconn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("reality handshake: %w (verified=%v)", err, rc.verified)
	}
	if !rc.verified {
		raw.Close()
		return nil, fmt.Errorf("reality: handshake not authenticated")
	}
	return chromeTLSConn{conn: uconn, state: rc.tlsState()}, nil
}
