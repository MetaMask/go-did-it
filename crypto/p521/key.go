package p521

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

const (
	// PublicKeyBytesSize is the size, in bytes, of public keys in raw bytes.
	PublicKeyBytesSize = 67
	// PrivateKeyBytesSize is the size, in bytes, of private keys in raw bytes.
	PrivateKeyBytesSize = 66
	// SignatureBytesSize is the size, in bytes, of signatures in raw bytes.
	SignatureBytesSize = 132

	MultibaseCode = uint64(0x1202)
)

func GenerateKeyPair() (*PublicKey, *PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub := priv.Public().(*ecdsa.PublicKey)
	return (*PublicKey)(pub), (*PrivateKey)(priv), nil
}

const (
	pemPubBlockType  = "PUBLIC KEY"
	pemPrivBlockType = "PRIVATE KEY"
)
