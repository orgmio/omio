package protocol

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func newH3Transport(addr string) *http3.Transport {
	return &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{http3.NextProtoH3},
			MinVersion:         tls.VersionTLS13,
		},
		DisableCompression: true,
		QUICConfig: &quic.Config{
			KeepAlivePeriod: 15 * time.Second,
			MaxIdleTimeout:  30 * time.Second,
		},
		Dial: func(ctx context.Context, _addr string, tlsCfg *tls.Config, qc *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, addr, tlsCfg, qc)
		},
	}
}

func connectHTTP3(ctx context.Context, tr *http3.Transport, addr, dest, token string) (net.Conn, error) {
	pr, pw := io.Pipe()
	u := &url.URL{Scheme: "https", Host: addr}
	req := (&http.Request{
		Method:        http.MethodConnect,
		URL:           u,
		Host:          dest,
		Header:        make(http.Header),
		Body:          pr,
		ContentLength: -1,
	}).WithContext(ctx)
	req.Header.Set("User-Agent", "")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		pr.Close()
		pw.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		pr.Close()
		pw.Close()
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("protocol: http/3 connect %s: status %s", dest, resp.Status)
	}
	return newConn(resp.Body, pw, staticAddr{"udp", "mio"}, staticAddr{"tcp", dest}), nil
}

func bearerToken(sum [32]byte) string {
	return hex.EncodeToString(sum[:])
}
