package ed25519

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/INFURA/go-did/crypto"
	"github.com/INFURA/go-did/crypto/internal"
)

var _ crypto.SigningPublicKey = &PublicKey{}

type PublicKey struct {
	k ed25519.PublicKey
}

// PublicKeyFromBytes converts a serialized public key to a PublicKey.
// This compact serialization format is the raw key material, without metadata or structure.
// It errors if the slice is not the right size.
func PublicKeyFromBytes(b []byte) (PublicKey, error) {
	if len(b) != PublicKeySize {
		return PublicKey{}, fmt.Errorf("invalid ed25519 public key size")
	}
	// make a copy
	return PublicKey{k: append([]byte{}, b...)}, nil
}

// PublicKeyFromPublicKeyMultibase decodes the public key from its PublicKeyMultibase form
func PublicKeyFromPublicKeyMultibase(multibase string) (PublicKey, error) {
	code, bytes, err := helpers.PublicKeyMultibaseDecode(multibase)
	if err != nil {
		return PublicKey{}, err
	}
	if code != MultibaseCode {
		return PublicKey{}, fmt.Errorf("invalid code")
	}
	if len(bytes) != PublicKeySize {
		return PublicKey{}, fmt.Errorf("invalid ed25519 public key size")
	}
	return PublicKeyFromBytes(bytes)
}

// PublicKeyFromX509DER decodes an X.509 DER (binary) encoded public key.
func PublicKeyFromX509DER(bytes []byte) (PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(bytes)
	if err != nil {
		return PublicKey{}, err
	}
	return PublicKey{k: pub.(ed25519.PublicKey)}, nil
}

// PublicKeyFromX509PEM decodes an X.509 PEM (string) encoded public key.
func PublicKeyFromX509PEM(str string) (PublicKey, error) {
	block, _ := pem.Decode([]byte(str))
	if block == nil {
		return PublicKey{}, fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != pemPubBlockType {
		return PublicKey{}, fmt.Errorf("incorrect PEM block type")
	}
	return PublicKeyFromX509DER(block.Bytes)
}

func (p PublicKey) ToBytes() []byte {
	// Copy the private key to a fixed size buffer that can get allocated on the
	// caller's stack after inlining.
	var buf [PublicKeySize]byte
	return append(buf[:0], p.k...)
}

func (p PublicKey) ToPublicKeyMultibase() string {
	return helpers.PublicKeyMultibaseEncode(MultibaseCode, p.k)
}

func (p PublicKey) ToX509DER() []byte {
	res, _ := x509.MarshalPKIXPublicKey(p.k)
	return res
}

func (p PublicKey) ToX509PEM() string {
	der := p.ToX509DER()
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  pemPubBlockType,
		Bytes: der,
	}))
}

func (p PublicKey) Equal(other crypto.PublicKey) bool {
	if other, ok := other.(PublicKey); ok {
		return p.k.Equal(other.k)
	}
	return false
}

func (p PublicKey) Verify(message, signature []byte) bool {
	return ed25519.Verify(p.k, message, signature)
}
