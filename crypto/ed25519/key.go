package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"

	"github.com/MetaMask/go-did-it/crypto"
)

const (
	// PublicKeyBytesSize is the size, in bytes, of public keys in raw bytes.
	PublicKeyBytesSize = ed25519.PublicKeySize
	// PrivateKeyBytesSize is the size, in bytes, of private keys in raw bytes.
	PrivateKeyBytesSize = ed25519.PrivateKeySize
	// SignatureBytesSize is the size, in bytes, of signatures in raw bytes.
	SignatureBytesSize = ed25519.SignatureSize

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

// KeyType returns the crypto.KeyType describing Ed25519, to be added to a crypto.KeySet.
func KeyType() crypto.KeyType {
	return crypto.KeyType{
		Name:         "Ed25519",
		Code:         MultibaseCode,
		DecodePublic: func(b []byte) (crypto.PublicKey, error) { return crypto.ToPub(PublicKeyFromBytes(b)) },
		Matches:      func(key crypto.PublicKey) bool { _, ok := key.(PublicKey); return ok },
	}
}
