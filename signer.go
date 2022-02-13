package signer

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"io/fs"
)

// Make sure RequestVerifier struct implements Verifier interface
var _ Signer = &RequestSigner{}

type RequestSigner struct {
	private ed25519.PrivateKey
	order   binary.ByteOrder
}

func NewSigner(keys fs.FS) (*RequestSigner, error) {
	return NewSignerWithNameAndOrder(keys, "private.key", binary.LittleEndian)
}

func NewSignerWithNameAndOrder(keys fs.FS, privateKeyName string, order binary.ByteOrder) (*RequestSigner, error) {
	contents, err := fs.ReadFile(keys, privateKeyName)

	if err != nil {
		return nil, err
	}

	return &RequestSigner{
		private: contents,
		order:   order,
	}, nil
}

func (r RequestSigner) SignString(payload []byte, timestamp uint64) string {
	return base64.RawURLEncoding.EncodeToString(r.Sign(payload, timestamp))
}

func (r RequestSigner) Sign(payload []byte, timestamp uint64) []byte {
	data := makePayload(payload, timestamp, r.order)

	return ed25519.Sign(r.private, data)
}
