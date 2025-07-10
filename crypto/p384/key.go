package p384

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

const (
	// PublicKeyBytesSize is the size, in bytes, of public keys in raw bytes.
	PublicKeyBytesSize = 1 + coordinateSize
	// PrivateKeyBytesSize is the size, in bytes, of private keys in raw bytes.
	PrivateKeyBytesSize = coordinateSize
	// SignatureBytesSize is the size, in bytes, of signatures in raw bytes.
	SignatureBytesSize = 2 * coordinateSize

	MultibaseCode = uint64(0x1201)

	// coordinateSize is the size, in bytes, of one coordinate in the elliptic curve.
	coordinateSize = 48
)

func GenerateKeyPair() (*PublicKey, *PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub := priv.Public().(*ecdsa.PublicKey)
	return &PublicKey{k: pub}, &PrivateKey{k: priv}, nil
}

const (
	pemPubBlockType  = "PUBLIC KEY"
	pemPrivBlockType = "PRIVATE KEY"
)
