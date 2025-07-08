package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

const (
	MultibaseCode = uint64(0x1205)

	MinRsaKeyBits = 2048
	MaxRsaKeyBits = 8192
)

func GenerateKeyPair(bits int) (*PublicKey, *PrivateKey, error) {
	if bits < MinRsaKeyBits || bits > MaxRsaKeyBits {
		return nil, nil, fmt.Errorf("invalid key size: %d", bits)
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return &PublicKey{k: &priv.PublicKey}, &PrivateKey{k: priv}, nil
}

const (
	pemPubBlockType  = "PUBLIC KEY"
	pemPrivBlockType = "PRIVATE KEY"
)
