package signer

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"github.com/stretchr/testify/require"
	"io/fs"
	"os"
	"testing"
	"testing/fstest"
	"time"
)

var verifierKeysFS = fstest.MapFS{
	"private.key": &fstest.MapFile{
		Data:    []byte{0, 123, 160, 198, 226, 126, 4, 1, 13, 62, 201, 155, 128, 19, 74, 125, 113, 217, 242, 34, 2, 233, 127, 234, 170, 93, 122, 131, 62, 88, 127, 164, 200, 195, 100, 58, 208, 187, 53, 206, 87, 4, 49, 24, 179, 86, 255, 166, 99, 140, 214, 16, 152, 188, 5, 137, 249, 169, 96, 65, 251, 112, 168, 8},
		Mode:    os.ModePerm,
		ModTime: time.Now(),
		Sys:     nil,
	},
	"public.key": &fstest.MapFile{
		Data:    []byte{200, 195, 100, 58, 208, 187, 53, 206, 87, 4, 49, 24, 179, 86, 255, 166, 99, 140, 214, 16, 152, 188, 5, 137, 249, 169, 96, 65, 251, 112, 168, 8},
		Mode:    os.ModePerm,
		ModTime: time.Now(),
		Sys:     nil,
	},
}

func TestNewVerifier(t *testing.T) {
	t.Parallel()
	assert := require.New(t)

	t.Run("KeyExists", func(t *testing.T) {
		_, err := NewVerifier(verifierKeysFS)

		assert.NoError(err)
	})

	t.Run("PublicKeyDoesNotExist", func(t *testing.T) {
		_, err := NewVerifierWithNameAndOrder(verifierKeysFS, "./not-found.key", binary.LittleEndian)

		assert.Error(err)
	})
}

func TestVerifyStringSignature(t *testing.T) {
	t.Parallel()
	assert := require.New(t)
	now := time.Now().UTC()
	t.Run("Success", func(t *testing.T) {
		public, _ := fs.ReadFile(verifierKeysFS, "public.key")
		private, _ := fs.ReadFile(verifierKeysFS, "private.key")
		r := RequestVerifier{
			public: public,
		}

		payload := []byte("Hello World")
		timestamp := uint64(now.Nanosecond())

		data := make([]byte, 8, 8+len(payload))

		binary.LittleEndian.PutUint64(data, timestamp)

		copy(data, payload)

		signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, data))

		assert.NoError(r.VerifyStringSignature(timestamp, payload, signature))
	})

	t.Run("InvalidBase64StringSignature", func(t *testing.T) {
		payload := []byte("Hello World")
		timestamp := uint64(now.Nanosecond())

		public, _ := fs.ReadFile(verifierKeysFS, "public.key")

		r := RequestVerifier{
			public: public,
		}

		assert.ErrorIs(ErrInvalidBase64Signature, r.VerifyStringSignature(timestamp, payload, "invalid-ba#$se64"))
	})

	t.Run("InvalidSignature", func(t *testing.T) {
		payload := []byte("Hello World")
		timestamp := uint64(now.Nanosecond())
		public, _ := fs.ReadFile(verifierKeysFS, "public.key")

		r := RequestVerifier{
			public: public,
		}

		assert.ErrorIs(ErrInvalidSignature, r.VerifyStringSignature(timestamp, payload, "validbase64butnotsignature"))
	})
}
