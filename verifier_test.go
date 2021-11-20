package signer

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewVerifier(t *testing.T) {
	t.Parallel()
	assert := require.New(t)

	t.Run("KeyExists", func(t *testing.T) {
		publicKeyPath, _, delete := generateKeys()

		defer delete()

		_, err := NewVerifier(publicKeyPath)

		assert.NoError(err)
	})

	t.Run("PublicKeyDoesNotExist", func(t *testing.T) {
		_, err := NewVerifier("./not-found.key")

		assert.Error(err)
	})
}

func TestVerifyStringSignature(t *testing.T) {
	t.Parallel()
	assert := require.New(t)
	now := time.Now().UTC()

	t.Run("Success", func(t *testing.T) {
		publicKeyPath, privateKeyPath, delete := generateKeys()

		privateKey, _ := os.ReadFile(privateKeyPath)

		defer delete()

		r := RequestVerifier{}

		assert.NoError(r.readKey(publicKeyPath))

		payload := []byte("Hello World")
		timestamp := uint64(now.Nanosecond())

		data := make([]byte, 8, 8+len(payload))

		binary.LittleEndian.PutUint64(data, timestamp)

		copy(data, payload)

		signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, data))

		assert.NoError(r.VerifyStringSignature(timestamp, payload, signature))
	})

	t.Run("InvalidBase64StringSignature", func(t *testing.T) {
		payload := []byte("Hello World")
		timestamp := uint64(now.Nanosecond())

		publicKeyPath, _, delete := generateKeys()

		public, _ := os.ReadFile(publicKeyPath)
		defer delete()

		r := RequestVerifier{
			public:        public,
		}

		assert.ErrorIs(ErrInvalidBase64Signature, r.VerifyStringSignature(timestamp, payload, "invalid-ba#$se64"))
	})

	t.Run("InvalidSignature", func(t *testing.T) {
		payload := []byte("Hello World")
		timestamp := uint64(now.Nanosecond())

		publicKeyPath, _, delete := generateKeys()

		public, _ := os.ReadFile(publicKeyPath)
		defer delete()

		r := RequestVerifier{
			public:        public,
		}

		assert.ErrorIs(ErrInvalidSignature, r.VerifyStringSignature(timestamp, payload, "validbase64butnotsignature"))
	})
}
