package allkeys

import (
	"fmt"

	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/ed25519"
	helpers "github.com/MetaMask/go-did-it/crypto/internal"
	"github.com/MetaMask/go-did-it/crypto/p256"
	"github.com/MetaMask/go-did-it/crypto/p384"
	"github.com/MetaMask/go-did-it/crypto/p521"
	"github.com/MetaMask/go-did-it/crypto/rsa"
	"github.com/MetaMask/go-did-it/crypto/secp256k1"
	"github.com/MetaMask/go-did-it/crypto/x25519"
)

var decoders = map[uint64]func(b []byte) (crypto.PublicKey, error){
	ed25519.MultibaseCode:   func(b []byte) (crypto.PublicKey, error) { return ed25519.PublicKeyFromBytes(b) },
	p256.MultibaseCode:      func(b []byte) (crypto.PublicKey, error) { return p256.PublicKeyFromBytes(b) },
	p384.MultibaseCode:      func(b []byte) (crypto.PublicKey, error) { return p384.PublicKeyFromBytes(b) },
	p521.MultibaseCode:      func(b []byte) (crypto.PublicKey, error) { return p521.PublicKeyFromBytes(b) },
	rsa.MultibaseCode:       func(b []byte) (crypto.PublicKey, error) { return rsa.PublicKeyFromPKCS1DER(b) },
	secp256k1.MultibaseCode: func(b []byte) (crypto.PublicKey, error) { return secp256k1.PublicKeyFromBytes(b) },
	x25519.MultibaseCode:    func(b []byte) (crypto.PublicKey, error) { return x25519.PublicKeyFromBytes(b) },
}

// PublicKeyFromPublicKeyMultibase decodes the public key from its PublicKeyMultibase form
func PublicKeyFromPublicKeyMultibase(multibase string) (crypto.PublicKey, error) {
	code, pubBytes, err := helpers.PublicKeyMultibaseDecode(multibase)
	if err != nil {
		return nil, fmt.Errorf("invalid publicKeyMultibase: %w", err)
	}
	decoder, ok := decoders[code]
	if !ok {
		return nil, fmt.Errorf("unsupported publicKeyMultibase code: %d", code)
	}
	return decoder(pubBytes)
}
