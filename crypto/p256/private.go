package p256

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/INFURA/go-did/crypto"
)

var _ crypto.SigningPrivateKey = (*PrivateKey)(nil)

type PrivateKey ecdsa.PrivateKey

// PrivateKeyFromBytes converts a serialized public key to a PrivateKey.
// This compact serialization format is the raw key material, without metadata or structure.
// It errors if the slice is not the right size.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	if len(b) != PrivateKeySize {
		return nil, fmt.Errorf("invalid P-256 private key size")
	}

	res := &ecdsa.PrivateKey{
		D:         new(big.Int).SetBytes(b),
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()},
	}

	// recompute the public key
	res.PublicKey.X, res.PublicKey.Y = res.PublicKey.Curve.ScalarBaseMult(b)

	return (*PrivateKey)(res), nil
}

// PrivateKeyFromPKCS8DER decodes a PKCS#8 DER (binary) encoded private key.
func PrivateKeyFromPKCS8DER(bytes []byte) (*PrivateKey, error) {
	priv, err := x509.ParsePKCS8PrivateKey(bytes)
	if err != nil {
		return nil, err
	}
	ecdsaPriv := priv.(*ecdsa.PrivateKey)
	return (*PrivateKey)(ecdsaPriv), nil
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
		return (*ecdsa.PrivateKey)(p).Equal((*ecdsa.PrivateKey)(other))
	}
	return false
}

func (p *PrivateKey) Public() crypto.PublicKey {
	ecdhPub := (*ecdsa.PrivateKey)(p).Public().(*ecdsa.PublicKey)
	return (*PublicKey)(ecdhPub)
}

func (p *PrivateKey) ToBytes() []byte {
	// fixed size buffer that can get allocated on the caller's stack after inlining.
	var buf [PrivateKeySize]byte
	((*ecdsa.PrivateKey)(p)).D.FillBytes(buf[:])
	return buf[:]
}

func (p *PrivateKey) ToPKCS8DER() []byte {
	res, _ := x509.MarshalPKCS8PrivateKey((*ecdsa.PrivateKey)(p))
	return res
}

func (p *PrivateKey) ToPKCS8PEM() string {
	der := p.ToPKCS8DER()
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  pemPrivBlockType,
		Bytes: der,
	}))
}

/*
	Note: signatures for the crypto.SigningPrivateKey interface assumes SHA256,
	which should be correct almost always. If there is a need to use a different
	hash function, we can add separate functions that have that flexibility.
*/

func (p *PrivateKey) SignToBytes(message []byte) ([]byte, error) {
	// Hash the message with SHA-256
	hash := sha256.Sum256(message)

	r, s, err := ecdsa.Sign(rand.Reader, (*ecdsa.PrivateKey)(p), hash[:])
	if err != nil {
		return nil, err
	}

	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])

	return sig, nil
}

func (p *PrivateKey) SignToASN1(message []byte) ([]byte, error) {
	// Hash the message with SHA-256
	hash := sha256.Sum256(message)

	// Use ecdsa.SignASN1 for direct ASN.1 DER encoding
	return ecdsa.SignASN1(rand.Reader, (*ecdsa.PrivateKey)(p), hash[:])

}
