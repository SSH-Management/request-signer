package signer

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"

	"github.com/SSH-Management/utils/v2"
)

// Make sure RequestVerifier struct implements Verifier interface
var _ Verifier = &RequestVerifier{}

type RequestVerifier struct {
	public ed25519.PublicKey
}

func NewVerifier(keyPath string) (RequestVerifier, error) {
	absPath , err := utils.GetAbsolutePath(keyPath)

	if err != nil {
		return RequestVerifier{}, err
	}

	r := RequestVerifier{}

	if err := r.readKey(absPath); err != nil {
		return RequestVerifier{}, err
	}

	return r, nil
}

func (r *RequestVerifier) readKey(path string) error {
	public, err := os.ReadFile(path)

	if err != nil {
		return err
	}

	r.public = public

	return nil
}


func (r RequestVerifier) VerifyStringSignature(timestamp uint64, payload []byte, signature string) error {
	signatureBytes, err := base64.RawURLEncoding.DecodeString(signature)

	if err != nil {
		return ErrInvalidBase64Signature
	}

	return r.Verify(timestamp, payload, signatureBytes)
}

func (r RequestVerifier) Verify(timestamp uint64, payload []byte, signature []byte) error {
	data := makePayload(payload, timestamp)

	if !ed25519.Verify(r.public, data, signature) {
		return ErrInvalidSignature
	}

	return nil
}
