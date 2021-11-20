package signer

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"

	"github.com/SSH-Management/utils/v2"
)

// Make sure RequestVerifier struct implements Verifier interface
var _ Signer = &RequestSigner{}

type RequestSigner struct {
	private ed25519.PrivateKey
}

func NewSigner(privateKeyPath string) (*RequestSigner, error) {
	privateKeyAbsPath, err := utils.GetAbsolutePath(privateKeyPath)

	if err != nil {
		return nil, err
	}

	r := &RequestSigner{}

	if err := r.readKey(privateKeyAbsPath); err != nil {
		return nil, err
	}

	return r, nil
}

func (r *RequestSigner) readKey(path string) error {
	private, err := os.ReadFile(path)

	if err != nil {
		return err
	}

	r.private = private

	return nil
}

func (r RequestSigner) SignString(payload []byte, timestamp uint64) string {
	return base64.RawURLEncoding.EncodeToString(r.Sign(payload, timestamp))
}

func (r RequestSigner) Sign(payload []byte, timestamp uint64) []byte {
	data := makePayload(payload, timestamp)

	return ed25519.Sign(r.private, data)
}
