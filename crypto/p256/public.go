package p256

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/INFURA/go-did/crypto"
	helpers "github.com/INFURA/go-did/crypto/internal"
)

var _ crypto.PublicKeySigningBytes = &PublicKey{}
var _ crypto.PublicKeySigningASN1 = &PublicKey{}
var _ crypto.PublicKeyToBytes = &PublicKey{}

type PublicKey struct {
	k *ecdsa.PublicKey
}

// PublicKeyFromBytes converts a serialized public key to a PublicKey.
// This compact serialization format is the raw key material, without metadata or structure.
// It errors if the slice is not the right size.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	if len(b) != PublicKeyBytesSize {
		return nil, fmt.Errorf("invalid P-256 public key size")
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), b)
	if x == nil {
		return nil, fmt.Errorf("invalid P-256 public key")
	}
	return &PublicKey{k: &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}}, nil
}

// PublicKeyFromXY converts x and y coordinates into a PublicKey.
func PublicKeyFromXY(x, y []byte) (*PublicKey, error) {
	pub := &PublicKey{k: &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}}

	if !elliptic.P256().IsOnCurve(pub.k.X, pub.k.Y) {
		return nil, fmt.Errorf("invalid P-256 public key")
	}
	return pub, nil
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
	return PublicKeyFromBytes(bytes)
}

// PublicKeyFromX509DER decodes an X.509 DER (binary) encoded public key.
func PublicKeyFromX509DER(bytes []byte) (*PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(bytes)
	if err != nil {
		return nil, err
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid public key")
	}
	return &PublicKey{k: ecdsaPub}, nil
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

func (p *PublicKey) XBytes() []byte {
	// fixed size buffer that can get allocated on the caller's stack after inlining.
	var buf [coordinateSize]byte
	(p.k).X.FillBytes(buf[:])
	return buf[:]
}

func (p *PublicKey) YBytes() []byte {
	// fixed size buffer that can get allocated on the caller's stack after inlining.
	var buf [coordinateSize]byte
	(p.k).Y.FillBytes(buf[:])
	return buf[:]
}

func (p *PublicKey) Equal(other crypto.PublicKey) bool {
	if other, ok := other.(*PublicKey); ok {
		return p.k.Equal(other.k)
	}
	return false
}

func (p *PublicKey) ToBytes() []byte {
	return elliptic.MarshalCompressed(elliptic.P256(), p.k.X, p.k.Y)
}

func (p *PublicKey) ToPublicKeyMultibase() string {
	bytes := elliptic.MarshalCompressed(elliptic.P256(), p.k.X, p.k.Y)
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

// The default signing hash is SHA-256.
func (p *PublicKey) VerifyBytes(message, signature []byte, opts ...crypto.SigningOption) bool {
	if len(signature) != SignatureBytesSize {
		return false
	}

	// For some reason, the go crypto library in ecdsa.Verify() encodes the signature as ASN.1 to then decode it.
	// This means it's actually more efficient to encode the signature as ASN.1 here.
	sigAsn1, err := helpers.EncodeSignatureToASN1(signature[:SignatureBytesSize/2], signature[SignatureBytesSize/2:])
	if err != nil {
		return false
	}

	return p.VerifyASN1(message, sigAsn1, opts...)
}

// The default signing hash is SHA-256.
func (p *PublicKey) VerifyASN1(message, signature []byte, opts ...crypto.SigningOption) bool {
	params := crypto.CollectSigningOptions(opts)

	hasher := params.HashOrDefault(crypto.SHA256).New()
	hasher.Write(message)
	hash := hasher.Sum(nil)

	return ecdsa.VerifyASN1(p.k, hash[:], signature)
}
