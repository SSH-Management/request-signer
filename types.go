package signer

import "crypto/ed25519"

type (
	RequestSigner struct {
		publicKeyPath  string
		privateKeyPath string

		private ed25519.PrivateKey
		public  ed25519.PublicKey
	}

	Interface interface {
		GenerateKeys() error
		Sign(data []byte) string
		Verify(timestamp uint64, payload []byte, signature string) error
	}
)
