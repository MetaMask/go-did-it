package x25519

import (
	"crypto/ecdh"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/INFURA/go-did/crypto"
	"github.com/INFURA/go-did/crypto/ed25519"
)

var _ crypto.PrivateKey = (*PrivateKey)(nil)

type PrivateKey ecdh.PrivateKey

// PrivateKeyFromBytes converts a serialized private key to a PrivateKey.
// This compact serialization format is the raw key material, without metadata or structure.
// It errors if len(privateKey) is not [PrivateKeySize].
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	// this already check the size of b
	priv, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return nil, err
	}
	return (*PrivateKey)(priv), nil
}

// PrivateKeyFromEd25519 converts an ed25519 private key to a x25519 private key.
// It errors if the slice is not the right size.
//
// This function is based on the algorithm described in https://datatracker.ietf.org/doc/html/draft-ietf-core-oscore-groupcomm#name-curve25519
func PrivateKeyFromEd25519(priv ed25519.PrivateKey) (*PrivateKey, error) {
	// get the 32-byte seed (first half of the private key)
	seed := priv.Seed()

	h := sha512.Sum512(seed)

	// clamp as per the X25519 spec
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64

	return PrivateKeyFromBytes(h[:32])
}

// PrivateKeyFromPKCS8DER decodes a PKCS#8 DER (binary) encoded private key.
func PrivateKeyFromPKCS8DER(bytes []byte) (*PrivateKey, error) {
	priv, err := x509.ParsePKCS8PrivateKey(bytes)
	if err != nil {
		return nil, err
	}
	ecdhPriv := priv.(*ecdh.PrivateKey)
	return (*PrivateKey)(ecdhPriv), nil
}

// PrivateKeyFromPKCS8PEM decodes an PKCS#8 PEM (string) encoded private key.
func PrivateKeyFromPKCS8PEM(str string) (*PrivateKey, error) {
	block, _ := pem.Decode([]byte(str))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != pemPrivBlockType {
		return nil, fmt.Errorf("incorrect PEM block type")
	}
	return PrivateKeyFromPKCS8DER(block.Bytes)
}

func (p *PrivateKey) Equal(other crypto.PrivateKey) bool {
	if other, ok := other.(*PrivateKey); ok {
		return (*ecdh.PrivateKey)(p).Equal((*ecdh.PrivateKey)(other))
	}
	return false
}

func (p *PrivateKey) Public() crypto.PublicKey {
	ecdhPub := (*ecdh.PrivateKey)(p).Public().(*ecdh.PublicKey)
	return (*PublicKey)(ecdhPub)
}

func (p *PrivateKey) ToBytes() []byte {
	return (*ecdh.PrivateKey)(p).Bytes()
}

func (p *PrivateKey) ToPKCS8DER() []byte {
	res, _ := x509.MarshalPKCS8PrivateKey((*ecdh.PrivateKey)(p))
	return res
}

func (p *PrivateKey) ToPKCS8PEM() string {
	der := p.ToPKCS8DER()
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  pemPrivBlockType,
		Bytes: der,
	}))
}
