package p384

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/INFURA/go-did/crypto"
	helpers "github.com/INFURA/go-did/crypto/internal"
)

var _ crypto.SigningPublicKey = (*PublicKey)(nil)

type PublicKey ecdsa.PublicKey

// PublicKeyFromBytes converts a serialized public key to a PublicKey.
// This compact serialization format is the raw key material, without metadata or structure.
// It errors if the slice is not the right size.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	if len(b) != PublicKeyBytesSize {
		return nil, fmt.Errorf("invalid P-384 public key size")
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P384(), b)
	if x == nil {
		return nil, fmt.Errorf("invalid P-384 public key")
	}
	return (*PublicKey)(&ecdsa.PublicKey{Curve: elliptic.P384(), X: x, Y: y}), nil
}

// PublicKeyFromXY converts x and y coordinates into a PublicKey.
func PublicKeyFromXY(x, y *big.Int) (*PublicKey, error) {
	if !elliptic.P384().IsOnCurve(x, y) {
		return nil, fmt.Errorf("invalid P-384 public key")
	}
	return (*PublicKey)(&ecdsa.PublicKey{Curve: elliptic.P384(), X: x, Y: y}), nil
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
	ecdsaPub := pub.(*ecdsa.PublicKey)
	return (*PublicKey)(ecdsaPub), nil
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

func (p *PublicKey) Equal(other crypto.PublicKey) bool {
	if other, ok := other.(*PublicKey); ok {
		return (*ecdsa.PublicKey)(p).Equal((*ecdsa.PublicKey)(other))
	}
	return false
}

func (p *PublicKey) ToBytes() []byte {
	ecdsaPub := (*ecdsa.PublicKey)(p)
	return elliptic.MarshalCompressed(elliptic.P384(), ecdsaPub.X, ecdsaPub.Y)
}

func (p *PublicKey) ToPublicKeyMultibase() string {
	ecdsaPub := (*ecdsa.PublicKey)(p)
	bytes := elliptic.MarshalCompressed(elliptic.P384(), ecdsaPub.X, ecdsaPub.Y)
	return helpers.PublicKeyMultibaseEncode(MultibaseCode, bytes)
}

func (p *PublicKey) ToX509DER() []byte {
	res, _ := x509.MarshalPKIXPublicKey((*ecdsa.PublicKey)(p))
	return res
}

func (p *PublicKey) ToX509PEM() string {
	der := p.ToX509DER()
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  pemPubBlockType,
		Bytes: der,
	}))
}

/*
	Note: signatures for the crypto.SigningPrivateKey interface assumes SHA384,
	which should be correct almost always. If there is a need to use a different
	hash function, we can add separate functions that have that flexibility.
*/

func (p *PublicKey) VerifyBytes(message, signature []byte) bool {
	if len(signature) != SignatureBytesSize {
		return false
	}

	// Hash the message with SHA-384
	hash := sha512.Sum384(message)

	r := new(big.Int).SetBytes(signature[:SignatureBytesSize/2])
	s := new(big.Int).SetBytes(signature[SignatureBytesSize/2:])

	return ecdsa.Verify((*ecdsa.PublicKey)(p), hash[:], r, s)
}

func (p *PublicKey) VerifyASN1(message, signature []byte) bool {
	// Hash the message with SHA-384
	hash := sha512.Sum384(message)

	return ecdsa.VerifyASN1((*ecdsa.PublicKey)(p), hash[:], signature)
}
