package signer

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"os"

	"github.com/SSH-Management/utils"
)


func NewSigner(publicKeyPath, privateKeyPath string) (RequestSigner, error) {
	publicKeyAbsPath, err := utils.GetAbsolutePath(publicKeyPath)

	if err != nil {
		return RequestSigner{}, err
	}

	privateKeyAbsPath, err := utils.GetAbsolutePath(privateKeyPath)

	if err != nil {
		return RequestSigner{}, err
	}

	r := RequestSigner{
		privateKeyPath: privateKeyAbsPath,
		publicKeyPath:  publicKeyAbsPath,
	}

	if !utils.FileExists(r.privateKeyPath) || !utils.FileExists(r.publicKeyPath) {
		if err := r.GenerateKeys(); err != nil {
			return RequestSigner{}, err
		}
	}

	if err := r.readKeys(); err != nil {
		return RequestSigner{}, err
	}

	return r, nil
}

func (r *RequestSigner) readKeys() error {
	private, err := os.ReadFile(r.privateKeyPath)

	if err != nil {
		return err
	}

	public, err := os.ReadFile(r.publicKeyPath)

	if err != nil {
		return err
	}

	r.private = private
	r.public = public

	return nil
}

func (r RequestSigner) Sign(data []byte) string {
	signature := ed25519.Sign(r.private, data)

	return base64.RawURLEncoding.EncodeToString(signature)
}

func (r RequestSigner) Verify(timestamp uint64, payload []byte, signature string) error {
	signatureBytes, err := base64.RawURLEncoding.DecodeString(signature)

	if err != nil {
		return err
	}

	data := make([]byte, 0, 8+len(payload))

	binary.LittleEndian.PutUint64(data, timestamp)

	copy(data, payload)

	if !ed25519.Verify(r.public, data, signatureBytes) {
		return ErrInvalidSignature
	}

	return nil
}

func (r RequestSigner) GenerateKeys() error {
	if utils.FileExists(r.privateKeyPath) && utils.FileExists(r.publicKeyPath) {
		return nil
	}

	public, private, err := ed25519.GenerateKey(nil)

	if err != nil {
		return err
	}

	if err := os.WriteFile(r.privateKeyPath, public, 0644); err != nil {
		_ = os.Remove(r.privateKeyPath)
		_ = os.Remove(r.publicKeyPath)
		return err
	}

	if err := os.WriteFile(r.privateKeyPath, private, 0600); err != nil {
		_ = os.Remove(r.privateKeyPath)
		_ = os.Remove(r.publicKeyPath)
		return err
	}

	return nil
}
