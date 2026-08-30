package handshake

import (
	"context"
	"crypto/tls"
	"errors"

	"github.com/orgmio/quic-mio/quicvarint"
	utls "github.com/orgmio/utls-mio"
	"github.com/orgmio/utls-mio/dicttls"
)

type tlsQUICConnection interface {
	Start(context.Context) error
	NextEvent() tls.QUICEvent
	Close() error
	HandleData(tls.QUICEncryptionLevel, []byte) error
	SetTransportParameters([]byte)
	StoreSession(*tls.SessionState) error
	SendSessionTicket(tls.QUICSessionTicketOptions) error
	ConnectionState() tls.ConnectionState
}

type standardQUICConn struct{ *tls.QUICConn }

func wrapStandardQUICConn(conn *tls.QUICConn) tlsQUICConnection { return &standardQUICConn{conn} }

func newStandardQUICClient(config *tls.Config) tlsQUICConnection {
	return wrapStandardQUICConn(tls.QUICClient(&tls.QUICConfig{
		TLSConfig:           config,
		EnableSessionEvents: true,
	}))
}

type chromeQUICConn struct{ conn *utls.UQUICConn }

func newChromeQUICClient(config *tls.Config, transportParameters []byte) tlsQUICConnection {
	uconfig := &utls.Config{
		Rand:                  config.Rand,
		Time:                  config.Time,
		RootCAs:               config.RootCAs,
		NextProtos:            append([]string(nil), config.NextProtos...),
		ServerName:            config.ServerName,
		InsecureSkipVerify:    config.InsecureSkipVerify,
		MinVersion:            utls.VersionTLS13,
		MaxVersion:            utls.VersionTLS13,
		KeyLogWriter:          config.KeyLogWriter,
		VerifyPeerCertificate: config.VerifyPeerCertificate,
	}
	conn := utls.UQUICClient(&utls.QUICConfig{TLSConfig: uconfig}, utls.HelloCustom)
	if err := conn.ApplyPreset(chromeQUICClientHello(transportParameters)); err != nil {
		panic("ixa quic-go: invalid Chromium ClientHello preset: " + err.Error())
	}
	conn.SetTransportParameters(transportParameters)
	return &chromeQUICConn{conn: conn}
}

func chromeQUICClientHello(rawTransportParameters []byte) *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin:         utls.VersionTLS13,
		TLSVersMax:         utls.VersionTLS13,
		CipherSuites:       []uint16{utls.TLS_AES_128_GCM_SHA256, utls.TLS_AES_256_GCM_SHA384, utls.TLS_CHACHA20_POLY1305_SHA256},
		CompressionMethods: []byte{0},
		Extensions: []utls.TLSExtension{
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{utls.CertCompressionBrotli}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.PSSWithSHA256, utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384, utls.PSSWithSHA384, utls.PKCS1WithSHA384,
				utls.PSSWithSHA512, utls.PKCS1WithSHA512, utls.PKCS1WithSHA1,
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.SNIExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"h3"}},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13}},
			&utls.GREASEEncryptedClientHelloExtension{
				CandidateCipherSuites: []utls.HPKESymmetricCipherSuite{{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_AES_128_GCM}},
				// Brave QUIC ECH extension data is 186 bytes in
				// way-brave-caddy-baidu.pcapng. GREASE payload is
				// inner+16 (GCM tag); plus 10-byte header and 32-byte
				// X25519 encapsulated key: 10+32+(128+16)=186.
				// 144 was producing 202 and did not match the capture.
				CandidatePayloadLens: []uint16{128},
			},
			&utls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h3"}},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519MLKEM768, utls.X25519, utls.CurveP256, utls.CurveP384}},
			&utls.QUICTransportParametersExtension{TransportParameters: decodeUTLSTransportParameters(rawTransportParameters)},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519MLKEM768}, {Group: utls.X25519}}},
		},
	}
}

func decodeUTLSTransportParameters(data []byte) utls.TransportParameters {
	var params utls.TransportParameters
	for len(data) > 0 {
		id, n, err := quicvarint.Parse(data)
		if err != nil {
			break
		}
		data = data[n:]
		length, n, err := quicvarint.Parse(data)
		if err != nil || length > uint64(len(data)-n) {
			break
		}
		data = data[n:]
		params = append(params, &utls.FakeQUICTransportParameter{Id: id, Val: append([]byte(nil), data[:length]...)})
		data = data[length:]
	}
	return params
}

func (c *chromeQUICConn) Start(ctx context.Context) error { return c.conn.Start(ctx) }
func (c *chromeQUICConn) Close() error                    { return c.conn.Close() }
func (c *chromeQUICConn) SetTransportParameters(p []byte) { c.conn.SetTransportParameters(p) }
func (c *chromeQUICConn) StoreSession(*tls.SessionState) error {
	return errors.New("uTLS QUIC session storage is disabled")
}
func (c *chromeQUICConn) SendSessionTicket(tls.QUICSessionTicketOptions) error {
	return errors.New("client cannot send a session ticket")
}
func (c *chromeQUICConn) HandleData(level tls.QUICEncryptionLevel, data []byte) error {
	return c.conn.HandleData(utls.QUICEncryptionLevel(level), data)
}
func (c *chromeQUICConn) NextEvent() tls.QUICEvent {
	e := c.conn.NextEvent()
	return tls.QUICEvent{Kind: tls.QUICEventKind(e.Kind), Level: tls.QUICEncryptionLevel(e.Level), Data: e.Data, Suite: e.Suite}
}
func (c *chromeQUICConn) ConnectionState() tls.ConnectionState {
	s := c.conn.ConnectionState()
	return tls.ConnectionState{Version: s.Version, HandshakeComplete: s.HandshakeComplete, DidResume: s.DidResume, CipherSuite: s.CipherSuite, NegotiatedProtocol: s.NegotiatedProtocol, NegotiatedProtocolIsMutual: s.NegotiatedProtocolIsMutual, ServerName: s.ServerName, PeerCertificates: s.PeerCertificates, VerifiedChains: s.VerifiedChains, SignedCertificateTimestamps: s.SignedCertificateTimestamps, OCSPResponse: s.OCSPResponse, TLSUnique: s.TLSUnique, ECHAccepted: s.ECHAccepted}
}
