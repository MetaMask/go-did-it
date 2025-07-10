package ed25519

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/cryptobyte"

	"github.com/ucan-wg/go-did-it/crypto"
)

var _ crypto.PrivateKeySigningBytes = &PrivateKey{}
var _ crypto.PrivateKeySigningASN1 = &PrivateKey{}
var _ crypto.PrivateKeyToBytes = &PrivateKey{}

type PrivateKey struct {
	k ed25519.PrivateKey
}

// PrivateKeyFromBytes converts a serialized private key to a PrivateKey.
// This compact serialization format is the raw key material, without metadata or structure.
// It errors if the slice is not the right size.
func PrivateKeyFromBytes(b []byte) (PrivateKey, error) {
	if len(b) != PrivateKeyBytesSize {
		return PrivateKey{}, fmt.Errorf("invalid ed25519 private key size")
	}
	// make a copy
	return PrivateKey{k: append([]byte{}, b...)}, nil
}

func PrivateKeyFromSeed(seed []byte) (PrivateKey, error) {
	if len(seed) != ed25519.SeedSize {
		return PrivateKey{}, fmt.Errorf("invalid ed25519 seed size")
	}
	return PrivateKey{k: ed25519.NewKeyFromSeed(seed)}, nil
}

// PrivateKeyFromPKCS8DER decodes a PKCS#8 DER (binary) encoded private key.
func PrivateKeyFromPKCS8DER(bytes []byte) (PrivateKey, error) {
	priv, err := x509.ParsePKCS8PrivateKey(bytes)
	if err != nil {
		return PrivateKey{}, err
	}
	edPriv, ok := priv.(ed25519.PrivateKey)
	if !ok {
		return PrivateKey{}, fmt.Errorf("invalid private key type")
	}
	return PrivateKey{k: edPriv}, nil
}

// PrivateKeyFromPKCS8PEM decodes an PKCS#8 PEM (string) encoded private key.
func PrivateKeyFromPKCS8PEM(str string) (PrivateKey, error) {
	block, _ := pem.Decode([]byte(str))
	if block == nil {
		return PrivateKey{}, fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != pemPrivBlockType {
		return PrivateKey{}, fmt.Errorf("incorrect PEM block type")
	}
	return PrivateKeyFromPKCS8DER(block.Bytes)
}

func (p PrivateKey) Equal(other crypto.PrivateKey) bool {
	if other, ok := other.(PrivateKey); ok {
		return p.k.Equal(other.k)
	}
	return false
}

func (p PrivateKey) Public() crypto.PublicKey {
	return PublicKey{k: p.k.Public().(ed25519.PublicKey)}
}

func (p PrivateKey) SignToBytes(message []byte, opts ...crypto.SigningOption) ([]byte, error) {
	params := crypto.CollectSigningOptions(opts)
	if params.Hash != crypto.Hash(0) && params.Hash != crypto.SHA512 {
		return nil, fmt.Errorf("ed25519 does not support custom hash functions")
	}
	return ed25519.Sign(p.k, message), nil
}

// SignToASN1 creates a signature with ASN.1 encoding.
// This ASN.1 encoding uses a BIT STRING, which would be correct for an X.509 certificate.
func (p PrivateKey) SignToASN1(message []byte, opts ...crypto.SigningOption) ([]byte, error) {
	params := crypto.CollectSigningOptions(opts)
	if params.Hash != crypto.Hash(0) && params.Hash != crypto.SHA512 {
		return nil, fmt.Errorf("ed25519 does not support custom hash functions")
	}
	sig := ed25519.Sign(p.k, message)
	var b cryptobyte.Builder
	b.AddASN1BitString(sig)
	return b.Bytes()
}

func (p PrivateKey) ToBytes() []byte {
	// Copy the private key to a fixed size buffer that can get allocated on the
	// caller's stack after inlining.
	var buf [PrivateKeyBytesSize]byte
	return append(buf[:0], p.k...)
}

func (p PrivateKey) ToPKCS8DER() []byte {
	res, _ := x509.MarshalPKCS8PrivateKey(p.k)
	return res
}

func (p PrivateKey) ToPKCS8PEM() string {
	der := p.ToPKCS8DER()
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  pemPrivBlockType,
		Bytes: der,
	}))
}

// Seed returns the private key seed corresponding to priv. It is provided for
// interoperability with RFC 8032. RFC 8032's private keys correspond to seeds
// in this package.
func (p PrivateKey) Seed() []byte {
	return p.k.Seed()
}
