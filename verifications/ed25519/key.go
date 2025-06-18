package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
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

	MultibaseCode = uint64(0xed)
)

func GenerateKeyPair() (PublicKey, PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// PublicKeyFromBytes converts a serialized public key to a PublicKey.
// This compact serialization format is the raw key material, without metadata or structure.
// It errors if the slice is not the right size.
func PublicKeyFromBytes(b []byte) (PublicKey, error) {
	if len(b) != PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key size")
	}
	// make a copy
	return PublicKey(append([]byte{}, b...)), nil
}

// PublicKeyToBytes converts a public key to a byte slice.
// This compact serialization format is the raw key material, without metadata or structure.
func PublicKeyToBytes(pub PublicKey) []byte {
	// Copy the private key to a fixed size buffer that can get allocated on the
	// caller's stack after inlining.
	var buf [PublicKeySize]byte
	return append(buf[:0], pub...)
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
	return PublicKeyFromBytes(bytes)
}

// PublicKeyToMultibase encodes the public key in a suitable way for publicKeyMultibase
func PublicKeyToMultibase(pub PublicKey) string {
	return helpers.MultibaseEncode(MultibaseCode, pub)
}

// PublicKeyFromX509DER decodes an X.509 DER (binary) encoded public key.
func PublicKeyFromX509DER(bytes []byte) (PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(bytes)
	if err != nil {
		return nil, err
	}
	return pub.(PublicKey), nil
}

// PublicKeyToX509DER encodes the public key into the X.509 DER (binary) format.
func PublicKeyToX509DER(pub PublicKey) []byte {
	res, _ := x509.MarshalPKIXPublicKey(pub)
	return res
}

const pemPubBlockType = "PUBLIC KEY"

// PublicKeyFromX509PEM decodes an X.509 PEM (string) encoded public key.
func PublicKeyFromX509PEM(str string) (PublicKey, error) {
	block, _ := pem.Decode([]byte(str))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != pemPubBlockType {
		return nil, fmt.Errorf("incorrect PEM block type")
	}
	return PublicKeyFromX509DER(block.Bytes)
}

// PublicKeyToX509PEM encodes the public key into the X.509 PEM (binary) format.
func PublicKeyToX509PEM(pub PublicKey) string {
	der := PublicKeyToX509DER(pub)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  pemPubBlockType,
		Bytes: der,
	}))
}

// PrivateKeyFromBytes converts a serialized private key to a PrivateKey.
// This compact serialization format is the raw key material, without metadata or structure.
// It errors if the slice is not the right size.
func PrivateKeyFromBytes(b []byte) (PrivateKey, error) {
	if len(b) != PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key size")
	}
	// make a copy
	return append([]byte{}, b...), nil
}

// PrivateKeyToBytes converts a private key to a byte slice.
// This compact serialization format is the raw key material, without metadata or structure.
func PrivateKeyToBytes(priv PrivateKey) []byte {
	// Copy the private key to a fixed size buffer that can get allocated on the
	// caller's stack after inlining.
	var buf [PrivateKeySize]byte
	return append(buf[:0], priv...)
}

// PrivateKeyFromPKCS8DER decodes a PKCS#8 DER (binary) encoded private key.
func PrivateKeyFromPKCS8DER(bytes []byte) (PrivateKey, error) {
	priv, err := x509.ParsePKCS8PrivateKey(bytes)
	if err != nil {
		return nil, err
	}
	return priv.(PrivateKey), nil
}

// PrivateKeyToPKCS8DER encodes the private key into the PKCS#8 DER (binary) format.
func PrivateKeyToPKCS8DER(priv PrivateKey) []byte {
	res, _ := x509.MarshalPKCS8PrivateKey(priv)
	return res
}

const pemPrivBlockType = "PRIVATE KEY"

// PrivateKeyFromPKCS8PEM decodes an PKCS#8 PEM (string) encoded private key.
func PrivateKeyFromPKCS8PEM(str string) (PrivateKey, error) {
	block, _ := pem.Decode([]byte(str))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != pemPrivBlockType {
		return nil, fmt.Errorf("incorrect PEM block type")
	}
	return PrivateKeyFromPKCS8DER(block.Bytes)
}

// PrivateKeyToPKCS8PEM encodes the private key into the PKCS#8 PEM (binary) format.
func PrivateKeyToPKCS8PEM(priv PrivateKey) string {
	der := PrivateKeyToPKCS8DER(priv)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  pemPrivBlockType,
		Bytes: der,
	}))
}

// Sign signs the message with privateKey and returns a signature.
// It will panic if len(privateKey) is not [PrivateKeySize].
func Sign(privateKey PrivateKey, message []byte) []byte {
	return ed25519.Sign(privateKey, message)
}
