package protocol

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
)

func connectHTTP1(raw net.Conn, dest string) (net.Conn, error) {
	req := "CONNECT " + dest + " HTTP/1.1\r\nHost: " + dest + "\r\n\r\n"
	if _, err := raw.Write([]byte(req)); err != nil {
		return nil, err
	}
	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("protocol: http/1.1 connect %s: status %s", dest, resp.Status)
	}
	var prefix []byte
	if n := br.Buffered(); n > 0 {
		prefix = make([]byte, n)
		_, _ = br.Read(prefix)
	}
	if len(prefix) == 0 {
		return raw, nil
	}
	return &prefixConn{Conn: raw, prefix: prefix}, nil
}
