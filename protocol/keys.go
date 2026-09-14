package protocol

import (
	"crypto/ecdh"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

type realityKeys struct {
	private []byte
	public  []byte
	shortID [8]byte
	token   [32]byte
}

func deriveKeys(password string) (realityKeys, error) {
	var k realityKeys
	r := hkdf.New(sha256.New, []byte(password), []byte("mio-reality"), []byte("x25519"))
	seed := make([]byte, 32)
	if _, err := io.ReadFull(r, seed); err != nil {
		return k, err
	}
	priv, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return k, fmt.Errorf("protocol: x25519 key: %w", err)
	}
	k.private = priv.Bytes()
	k.public = priv.PublicKey().Bytes()
	sid := hkdf.New(sha256.New, []byte(password), []byte("mio-reality"), []byte("shortid"))
	if _, err := io.ReadFull(sid, k.shortID[:]); err != nil {
		return k, err
	}
	k.token = sha256.Sum256([]byte("mio-token:" + password))
	return k, nil
}
