package signer

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"io/fs"
)

// Make sure RequestVerifier struct implements Verifier interface
var _ Verifier = &RequestVerifier{}

type RequestVerifier struct {
	public ed25519.PublicKey
	order  binary.ByteOrder
}

func NewVerifier(keys fs.FS) (*RequestVerifier, error) {
	return NewVerifierWithNameAndOrder(keys, "public.key", binary.LittleEndian)
}

func NewVerifierWithNameAndOrder(keys fs.FS, publicKeyName string, order binary.ByteOrder) (*RequestVerifier, error) {
	contents, err := fs.ReadFile(keys, publicKeyName)

	if err != nil {
		return nil, err
	}

	return &RequestVerifier{
		public: contents,
		order:  order,
	}, nil
}

func (r RequestVerifier) VerifyStringSignature(timestamp uint64, payload []byte, signature string) error {
	signatureBytes, err := base64.RawURLEncoding.DecodeString(signature)

	if err != nil {
		return ErrInvalidBase64Signature
	}

	return r.Verify(timestamp, payload, signatureBytes)
}

func (r RequestVerifier) Verify(timestamp uint64, payload []byte, signature []byte) error {
	data := makePayload(payload, timestamp, r.order)

	if !ed25519.Verify(r.public, data, signature) {
		return ErrInvalidSignature
	}

	return nil
}
