package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/INFURA/go-did/verifications/internal"
)

type PublicKey = ed25519.PublicKey
type PrivateKey = ed25519.PrivateKey

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = ed25519.PublicKeySize
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = ed25519.PrivateKeySize
	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = ed25519.SignatureSize
)

func GenerateKeyPair() (PublicKey, PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// PublicKeyFromBytes converts a serialized public key to a PublicKey.
// It errors if the slice is not the right size.
func PublicKeyFromBytes(b []byte) (PublicKey, error) {
	if len(b) != PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key size")
	}
	return PublicKey(b), nil
}

// PublicKeyFromMultibase decodes the public key from its Multibase form
func PublicKeyFromMultibase(multibase string) (PublicKey, error) {
	code, bytes, err := helpers.MultibaseDecode(multibase)
	if err != nil {
		return nil, err
	}
	if code != MultibaseCode {
		return nil, fmt.Errorf("invalid code")
	}
	if len(bytes) != PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key size")
	}
	return bytes, nil
}

// PublicKeyToMultibase encodes the public key in a suitable way for publicKeyMultibase
func PublicKeyToMultibase(pub PublicKey) string {
	return helpers.MultibaseEncode(MultibaseCode, pub)
}

// PrivateKeyFromBytes converts a serialized public key to a PrivateKey.
// It errors if the slice is not the right size.
func PrivateKeyFromBytes(b []byte) (PrivateKey, error) {
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key size")
	}
	return b, nil
}

// Sign signs the message with privateKey and returns a signature.
// It will panic if len(privateKey) is not [PrivateKeySize].
func Sign(privateKey PrivateKey, message []byte) []byte {
	return ed25519.Sign(privateKey, message)
}
