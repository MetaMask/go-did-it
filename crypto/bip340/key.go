package bip340

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	// PublicKeyBytesSize is the size, in bytes, of public keys as x-only (BIP-340 format).
	PublicKeyBytesSize = 32
	// PrivateKeyBytesSize is the size, in bytes, of private keys in raw bytes.
	PrivateKeyBytesSize = secp256k1.PrivKeyBytesLen
	// SignatureBytesSize is the size, in bytes, of BIP-340 signatures.
	SignatureBytesSize = 64

	// code waiting for approval: https://github.com/multiformats/multicodec/pull/398
	MultibaseCode = uint64(0x1340)
)

// GenerateKeyPair generates a new BIP-340 keypair.
// The private key is normalized so the public key always has an even Y coordinate,
// enabling lossless x-only serialization.
func GenerateKeyPair() (*PublicKey, *PrivateKey, error) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, nil, err
	}
	if priv.PubKey().Y().Bit(0) != 0 {
		priv.Key.Negate()
	}
	return &PublicKey{k: priv.PubKey()}, &PrivateKey{k: priv}, nil
}
