package signer

import "errors"

var (
	ErrInvalidSignature = errors.New("signature is invalid")
	ErrKeysAlreadyExist = errors.New("public and private keys already exist")
	ErrInvalidBase64Signature = errors.New("signature is not base64url encoded")
)

