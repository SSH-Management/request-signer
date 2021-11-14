package signer

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateKeys(t *testing.T) {
	t.Parallel()
	assert := require.New(t)

	defer func() {
		os.RemoveAll("./keys")
	}()

	r := RequestSigner{
		publicKeyPath: "./keys/public.key",
		privateKeyPath: "./keys/private.key",
	}

	assert.NoError(r.GenerateKeys())
}
