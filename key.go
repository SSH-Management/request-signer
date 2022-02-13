package signer

import (
	"crypto/ed25519"
	"os"

	"github.com/SSH-Management/utils/v2"
)

var _ KeyGenerator = &Ed25519KeyGenerator{}

type Ed25519KeyGenerator struct {
	privateKeyPath string
	publicKeyPath  string
}

func NewKeyGenerator(privateKeyPath, publicKeyPath string) (*Ed25519KeyGenerator, error) {
	privateKeyAbsPath, err := utils.GetAbsolutePath(privateKeyPath)

	if err != nil {
		return nil, err
	}

	publicKeyAbsPath, err := utils.GetAbsolutePath(publicKeyPath)

	if err != nil {
		return nil, err
	}

	return &Ed25519KeyGenerator{
		privateKeyPath: privateKeyAbsPath,
		publicKeyPath:  publicKeyAbsPath,
	}, nil
}

func (r Ed25519KeyGenerator) Generate() error {
	if utils.FileExists(r.privateKeyPath) && utils.FileExists(r.publicKeyPath) {
		return ErrKeysAlreadyExist
	}

	if _, err := utils.CreateDirectoryFromFile(r.privateKeyPath, 0744); err != nil {
		return err
	}

	if _, err := utils.CreateDirectoryFromFile(r.publicKeyPath, 0744); err != nil {
		return err
	}

	public, private, err := ed25519.GenerateKey(nil)

	if err != nil {
		return err
	}

	if err = os.WriteFile(r.publicKeyPath, public, 0644); err != nil {
		_ = os.Remove(r.publicKeyPath)
		return err
	}

	if err = os.WriteFile(r.privateKeyPath, private, 0600); err != nil {
		_ = os.Remove(r.privateKeyPath)
		_ = os.Remove(r.publicKeyPath)
		return err
	}

	return nil
}
