package x25519

import (
	"crypto/ecdh"
	"crypto/rand"
)

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = 32
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 32
	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = 32

	MultibaseCode = uint64(0xec)
)

func GenerateKeyPair() (*PublicKey, *PrivateKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub := priv.Public().(*ecdh.PublicKey)
	return (*PublicKey)(pub), (*PrivateKey)(priv), nil
}

const (
	pemPubBlockType  = "PUBLIC KEY"
	pemPrivBlockType = "PRIVATE KEY"
)
