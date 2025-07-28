package p384

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/MetaMask/go-did-it/crypto"
)

var _ crypto.PrivateKeySigningBytes = &PrivateKey{}
var _ crypto.PrivateKeySigningASN1 = &PrivateKey{}
var _ crypto.PrivateKeyToBytes = &PrivateKey{}
var _ crypto.PrivateKeyKeyExchange = &PrivateKey{}

type PrivateKey struct {
	k *ecdsa.PrivateKey
}

// PrivateKeyFromBytes converts a serialized public key to a PrivateKey.
// This compact serialization format is the raw key material, without metadata or structure.
// It errors if the slice is not the right size.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	if len(b) != PrivateKeyBytesSize {
		return nil, fmt.Errorf("invalid P-384 private key size")
	}

	res := &PrivateKey{
		k: &ecdsa.PrivateKey{
			D:         new(big.Int).SetBytes(b),
			PublicKey: ecdsa.PublicKey{Curve: elliptic.P384()},
		},
	}

	// recompute the public key
	res.k.PublicKey.X, res.k.PublicKey.Y = res.k.PublicKey.Curve.ScalarBaseMult(b)

	return res, nil
}

// PrivateKeyFromPKCS8DER decodes a PKCS#8 DER (binary) encoded private key.
func PrivateKeyFromPKCS8DER(bytes []byte) (*PrivateKey, error) {
	priv, err := x509.ParsePKCS8PrivateKey(bytes)
	if err != nil {
		return nil, err
	}
	ecdsaPriv, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid private key type")
	}
	return &PrivateKey{k: ecdsaPriv}, nil
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
		return p.k.Equal(other.k)
	}
	return false
}

func (p *PrivateKey) Public() crypto.PublicKey {
	ecdhPub := p.k.Public().(*ecdsa.PublicKey)
	return &PublicKey{k: ecdhPub}
}

func (p *PrivateKey) ToBytes() []byte {
	// fixed size buffer that can get allocated on the caller's stack after inlining.
	var buf [PrivateKeyBytesSize]byte
	(p.k).D.FillBytes(buf[:])
	return buf[:]
}

func (p *PrivateKey) ToPKCS8DER() []byte {
	res, _ := x509.MarshalPKCS8PrivateKey(p.k)
	return res
}

func (p *PrivateKey) ToPKCS8PEM() string {
	der := p.ToPKCS8DER()
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  pemPrivBlockType,
		Bytes: der,
	}))
}

// The default signing hash is SHA-384.
func (p *PrivateKey) SignToBytes(message []byte, opts ...crypto.SigningOption) ([]byte, error) {
	params := crypto.CollectSigningOptions(opts)

	hasher := params.HashOrDefault(crypto.SHA384).New()
	hasher.Write(message)
	hash := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, p.k, hash[:])
	if err != nil {
		return nil, err
	}

	sig := make([]byte, SignatureBytesSize)
	r.FillBytes(sig[:SignatureBytesSize/2])
	s.FillBytes(sig[SignatureBytesSize/2:])

	return sig, nil
}

// The default signing hash is SHA-384.
func (p *PrivateKey) SignToASN1(message []byte, opts ...crypto.SigningOption) ([]byte, error) {
	params := crypto.CollectSigningOptions(opts)

	hasher := params.HashOrDefault(crypto.SHA384).New()
	hasher.Write(message)
	hash := hasher.Sum(nil)

	return ecdsa.SignASN1(rand.Reader, p.k, hash[:])
}

func (p *PrivateKey) PublicKeyIsCompatible(remote crypto.PublicKey) bool {
	if _, ok := remote.(*PublicKey); ok {
		return true
	}
	return false
}

func (p *PrivateKey) KeyExchange(remote crypto.PublicKey) ([]byte, error) {
	if remote, ok := remote.(*PublicKey); ok {
		// First, we need to convert the ECDSA (signing only) to the equivalent ECDH keys
		ecdhPriv, err := p.k.ECDH()
		if err != nil {
			return nil, err
		}
		ecdhPub, err := remote.k.ECDH()
		if err != nil {
			return nil, err
		}

		return ecdhPriv.ECDH(ecdhPub)
	}
	return nil, fmt.Errorf("incompatible public key")
}
