package signer

import (
	"crypto/ed25519"
	"fmt"
	"github.com/SSH-Management/utils/v2"
	"math/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func generateKeys() (string, string, func()) {
	dirRand := rand.Int31n(400)
	fileRand := rand.Int31n(400)

	privateKeyFile, pubicKeyFile := fmt.Sprintf("./keys-%d/private-%d.key", dirRand, fileRand), fmt.Sprintf("./keys-%d/public-%d.key", dirRand, fileRand)

	_, _ = utils.CreateDirectoryFromFile(privateKeyFile, 0744)

	public, private, _ := ed25519.GenerateKey(nil)

	_ = os.WriteFile(pubicKeyFile, public, 0644)
	_ = os.WriteFile(privateKeyFile, private, 0600)

	return pubicKeyFile, privateKeyFile, func() {
		_ = os.RemoveAll(fmt.Sprintf("./keys-%d", dirRand))
	}
}

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
		_ = os.RemoveAll("./keys")
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
		publicKey, privateKey, clean := generateKeys()

		defer clean()

		r := Ed25519KeyGenerator{
			publicKeyPath:  publicKey,
			privateKeyPath: privateKey,
		}

		assert.ErrorIs(ErrKeysAlreadyExist, r.Generate())
	})
}
