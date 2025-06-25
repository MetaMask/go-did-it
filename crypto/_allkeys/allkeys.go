package allkeys

import (
	"fmt"

	"github.com/INFURA/go-did/crypto"
	"github.com/INFURA/go-did/crypto/ed25519"
	helpers "github.com/INFURA/go-did/crypto/internal"
	"github.com/INFURA/go-did/crypto/p256"
	"github.com/INFURA/go-did/crypto/p384"
	"github.com/INFURA/go-did/crypto/x25519"
)

var decoders = map[uint64]func(b []byte) (crypto.PublicKey, error){
	ed25519.MultibaseCode: func(b []byte) (crypto.PublicKey, error) { return ed25519.PublicKeyFromBytes(b) },
	p256.MultibaseCode:    func(b []byte) (crypto.PublicKey, error) { return p256.PublicKeyFromBytes(b) },
	p384.MultibaseCode:    func(b []byte) (crypto.PublicKey, error) { return p384.PublicKeyFromBytes(b) },
	x25519.MultibaseCode:  func(b []byte) (crypto.PublicKey, error) { return x25519.PublicKeyFromBytes(b) },
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
