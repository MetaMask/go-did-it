package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
)

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = ed25519.PublicKeySize
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = ed25519.PrivateKeySize
	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = ed25519.SignatureSize

	MultibaseCode = uint64(0xed)
)

func GenerateKeyPair() (PublicKey, PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return PublicKey{}, PrivateKey{}, err
	}
	return PublicKey{k: pub}, PrivateKey{k: priv}, nil
}

const (
	pemPubBlockType  = "PUBLIC KEY"
	pemPrivBlockType = "PRIVATE KEY"
)
