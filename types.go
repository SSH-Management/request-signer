package signer

type (
	Signer interface{
		Sign([]byte, uint64) []byte
		SignString([]byte, uint64) string

		readKey(string) error
	}

	Verifier interface{
		Verify(uint64, []byte, []byte) error
		VerifyStringSignature(uint64, []byte, string) error

		readKey(string) error
	}

	KeyGenerator interface {
		Generate() error
	}
)
