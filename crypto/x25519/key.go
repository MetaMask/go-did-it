package x25519

import (
	"crypto/ecdh"
	"crypto/rand"
	"math/big"

	"github.com/MetaMask/go-did-it/crypto"
)

const (
	// PublicKeyBytesSize is the size, in bytes, of public keys in raw bytes.
	PublicKeyBytesSize = 32
	// PrivateKeyBytesSize is the size, in bytes, of private keys in raw bytes.
	PrivateKeyBytesSize = 32

	MultibaseCode = uint64(0xec)
)

func GenerateKeyPair() (*PublicKey, *PrivateKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub := priv.Public().(*ecdh.PublicKey)
	return &PublicKey{k: pub}, &PrivateKey{k: priv}, nil
}

const (
	pemPubBlockType  = "PUBLIC KEY"
	pemPrivBlockType = "PRIVATE KEY"
)

// curve25519P is the field prime 2^255 - 19.
//
// Equivalent to:
// two := big.NewInt(2)
// exp := big.NewInt(255)
// p := new(big.Int).Exp(two, exp, nil)
// p.Sub(p, big.NewInt(19))
var curve25519P = new(big.Int).SetBytes([]byte{
	0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed,
})

// curve25519PMinusOne is p - 1, the largest canonical field element.
var curve25519PMinusOne = new(big.Int).Sub(curve25519P, big.NewInt(1))

var one = big.NewInt(1)

// KeyType returns the crypto.KeyType describing X25519, to be added to a crypto.KeySet.
func KeyType() crypto.KeyType {
	return crypto.KeyType{
		Name:         "X25519",
		Code:         MultibaseCode,
		DecodePublic: func(b []byte) (crypto.PublicKey, error) { return crypto.ToPub(PublicKeyFromBytes(b)) },
		Matches:      func(key crypto.PublicKey) bool { _, ok := key.(*PublicKey); return ok },
	}
}
