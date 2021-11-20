package signer

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewKeyGenerator(t *testing.T) {
	t.Parallel()
	assert := require.New(t)

	_, err := NewKeyGenerator("./keys/private.key", "./keys/public.key")

	assert.NoError(err)
}

func TestGenerateKeys(t *testing.T) {
	t.Parallel()
	assert := require.New(t)

	defer func() {
		os.RemoveAll("./keys")
	}()

	t.Run("KeysDoNotExist", func(t *testing.T) {
		r := Ed25519KeyGenerator{
			publicKeyPath:  "./keys/public.key",
			privateKeyPath: "./keys/private.key",
		}

		assert.NoError(r.Generate())
		assert.DirExists("./keys")
		assert.FileExists("./keys/public.key")
		assert.FileExists("./keys/private.key")
	})

	t.Run("KeysExist", func(t *testing.T) {
		publicKey, privateKey, delete := generateKeys()

		defer delete()

		r := Ed25519KeyGenerator{
			publicKeyPath:  publicKey,
			privateKeyPath: privateKey,
		}

		assert.ErrorIs(ErrKeysAlreadyExist, r.Generate())
	})
}
