package signer

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/SSH-Management/utils/v2"
	"github.com/stretchr/testify/require"
)

func generateKeys() (string, string, func()) {
	dirRand := rand.Int31n(400)
	fileRand := rand.Int31n(400)

	privateKeyFile, pubicKeyFile := fmt.Sprintf("./keys-%d/private-%d.key", dirRand, fileRand), fmt.Sprintf("./keys-%d/public-%d.key", dirRand, fileRand)

	utils.CreateDirectoryFromFile(privateKeyFile, 0744);
 	utils.CreateDirectoryFromFile(pubicKeyFile, 0744)

	public, private, _ := ed25519.GenerateKey(nil)

	os.WriteFile(pubicKeyFile, public, 0644)
	os.WriteFile(privateKeyFile, private, 0600)

	return pubicKeyFile, privateKeyFile, func() {
		os.RemoveAll(fmt.Sprintf("./keys-%d", dirRand))
	}
}

func TestNewSigner(t *testing.T) {
	t.Parallel()
	assert := require.New(t)

	t.Run("KeyExists", func(t *testing.T) {
		publicKeyPath, _, delete := generateKeys()

		defer delete()

		_, err := NewSigner(publicKeyPath)

		assert.NoError(err)
	})

	t.Run("PublicKeyDoesNotExist", func(t *testing.T) {
		_, err := NewSigner("./not-found.key")

		assert.Error(err)
	})
}


func TestSignString(t *testing.T) {
	t.Parallel()
	assert := require.New(t)
	now := time.Now().UTC()

	_, privateKeyPath, delete := generateKeys()

	defer delete()

	r := RequestSigner{}

	assert.NoError(r.readKey(privateKeyPath))

	payload := []byte("Hello World")
	timestamp := uint64(now.Nanosecond())

	signed := r.SignString(payload, timestamp)
	data := make([]byte, 8, 8+len(payload))

	binary.LittleEndian.PutUint64(data, timestamp)

	copy(data, payload)

	signature := ed25519.Sign(r.private, data)

	expected := base64.RawURLEncoding.EncodeToString(signature)

	assert.Equal(expected, signed)
}

