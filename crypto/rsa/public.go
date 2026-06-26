package rsa

import (
	stdcrypto "crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/ucan-wg/go-varsig"

	"github.com/MetaMask/go-did-it/crypto"
	helpers "github.com/MetaMask/go-did-it/crypto/internal"
)

var _ crypto.PublicKeySigningASN1 = &PublicKey{}
var _ crypto.PublicKeyX509 = &PublicKey{}

type PublicKey struct {
	k *rsa.PublicKey
}

func PublicKeyFromPKCS1DER(bytes []byte) (*PublicKey, error) {
	pub, err := x509.ParsePKCS1PublicKey(bytes)
	if err != nil {
		return nil, err
	}
	if err := validatePublicKey(pub); err != nil {
		return nil, err
	}
	return &PublicKey{k: pub}, nil
}

func PublicKeyFromNE(n, e []byte) (*PublicKey, error) {
	nBInt := new(big.Int).SetBytes(n)
	eBInt := new(big.Int).SetBytes(e)
	if !eBInt.IsInt64() {
		return nil, fmt.Errorf("invalid exponent")
	}
	pub := &rsa.PublicKey{N: nBInt, E: int(eBInt.Int64())}
	if err := validatePublicKey(pub); err != nil {
		return nil, err
	}
	return &PublicKey{k: pub}, nil
}

// PublicKeyFromPublicKeyMultibase decodes the public key from its Multibase form
func PublicKeyFromPublicKeyMultibase(multibase string) (*PublicKey, error) {
	code, bytes, err := helpers.PublicKeyMultibaseDecode(multibase)
	if err != nil {
		return nil, err
	}
	if code != MultibaseCode {
		return nil, fmt.Errorf("invalid code")
	}
	// The did:key spec encodes the RSA public key as PKCS#1 (RSAPublicKey) DER.
	return PublicKeyFromPKCS1DER(bytes)
}

// PublicKeyFromX509DER decodes an X.509 DER (binary) encoded public key.
func PublicKeyFromX509DER(bytes []byte) (*PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid public key")
	}
	if err := validatePublicKey(rsaPub); err != nil {
		return nil, err
	}
	return &PublicKey{k: rsaPub}, nil
}

// PublicKeyFromX509PEM decodes an X.509 PEM (string) encoded public key.
func PublicKeyFromX509PEM(str string) (*PublicKey, error) {
	block, _ := pem.Decode([]byte(str))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != pemPubBlockType {
		return nil, fmt.Errorf("incorrect PEM block type")
	}
	return PublicKeyFromX509DER(block.Bytes)
}

func validatePublicKey(pub *rsa.PublicKey) error {
	if pub == nil || pub.N == nil {
		return fmt.Errorf("invalid public key")
	}
	if pub.N.Sign() <= 0 {
		return fmt.Errorf("invalid modulus")
	}
	if pub.N.BitLen() < MinRsaKeyBits {
		return fmt.Errorf("key length too small")
	}
	if pub.N.BitLen() > MaxRsaKeyBits {
		return fmt.Errorf("key length too large")
	}
	if pub.N.Bit(0) == 0 {
		return fmt.Errorf("modulus must be odd")
	}
	if pub.E <= 0 {
		return fmt.Errorf("exponent must be positive")
	}
	if pub.E < 2 {
		return fmt.Errorf("exponent too small")
	}
	if pub.E%2 == 0 {
		return fmt.Errorf("exponent must be odd")
	}
	return nil
}

func (p *PublicKey) KeyLength() uint64 {
	return uint64((p.k.N.BitLen() + 7) / 8) // Round up to the nearest byte
}

func (p *PublicKey) NBytes() []byte {
	return p.k.N.Bytes()
}

func (p *PublicKey) EBytes() []byte {
	return new(big.Int).SetInt64(int64(p.k.E)).Bytes()
}

func (p *PublicKey) Equal(other crypto.PublicKey) bool {
	if other, ok := other.(*PublicKey); ok {
		return p.k.Equal(other.k)
	}
	return false
}

func (p *PublicKey) ToPublicKeyMultibase() string {
	// The did:key spec encodes the RSA public key as PKCS#1 (RSAPublicKey) DER.
	bytes := x509.MarshalPKCS1PublicKey(p.k)
	return helpers.PublicKeyMultibaseEncode(MultibaseCode, bytes)
}

func (p *PublicKey) ToX509DER() []byte {
	res, _ := x509.MarshalPKIXPublicKey(p.k)
	return res
}

func (p *PublicKey) ToX509PEM() string {
	der := p.ToX509DER()
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  pemPubBlockType,
		Bytes: der,
	}))
}

// VerifyASN1 verifies a PKCS#1 v1.5 signature.
// The default signing hash is:
// - SHA-256 for keys of length 2048 bits and under
// - SHA-384 for keys of length 3072 bits and under
// - SHA-512 for higher key length
func (p *PublicKey) VerifyASN1(message, signature []byte, opts ...crypto.SigningOption) bool {
	params := crypto.CollectSigningOptions(opts)

	if !params.VarsigMatch(varsig.AlgorithmRSA, 0, p.KeyLength()) {
		return false
	}

	hashCode := params.HashOrDefault(defaultSigHash(p.k.N.BitLen()))
	if hashCode == crypto.PREHASHED {
		return false
	}
	hasher := hashCode.New()
	hasher.Write(message)
	hash := hasher.Sum(nil)

	err := rsa.VerifyPKCS1v15(p.k, stdcrypto.Hash(hashCode), hash, signature)
	return err == nil
}

// Unwrap returns the underlying crypto/rsa public key.
func (p *PublicKey) Unwrap() *rsa.PublicKey {
	return p.k
}
