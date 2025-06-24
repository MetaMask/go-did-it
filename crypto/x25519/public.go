package x25519

import (
	"crypto/ecdh"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/INFURA/go-did/crypto"
	"github.com/INFURA/go-did/crypto/ed25519"
	helpers "github.com/INFURA/go-did/crypto/internal"
)

var _ crypto.PublicKey = (*PublicKey)(nil)

type PublicKey ecdh.PublicKey

// PublicKeyFromBytes converts a serialized public key to a PublicKey.
// This compact serialization format is the raw key material, without metadata or structure.
// It errors if the slice is not the right size.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	pub, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		return nil, err
	}
	return (*PublicKey)(pub), nil
}

// PublicKeyFromEd25519 converts an ed25519 public key to a x25519 public key.
// It errors if the slice is not the right size.
//
// This function is based on the algorithm described in https://datatracker.ietf.org/doc/html/draft-ietf-core-oscore-groupcomm#name-curve25519
func PublicKeyFromEd25519(pub ed25519.PublicKey) (*PublicKey, error) {
	// Conversion formula is u = (1 + y) / (1 - y) (mod p)
	// See https://datatracker.ietf.org/doc/html/draft-ietf-core-oscore-groupcomm#name-ecdh-with-montgomery-coordi

	pubBytes := pub.ToBytes()

	// Clear the sign bit (MSB of last byte)
	// This is because ed25519 serialize as bytes with 255 bit for Y, and one bit for the sign.
	// We only want Y, and the sign is irrelevant for the conversion.
	pubBytes[ed25519.PublicKeyBytesSize-1] &= 0x7F

	// ed25519 are little-endian, but big.Int expects big-endian
	// See https://www.rfc-editor.org/rfc/rfc8032
	y := new(big.Int).SetBytes(reverseBytes(pubBytes))
	one := big.NewInt(1)
	negOne := big.NewInt(-1)

	if y.Cmp(one) == 0 || y.Cmp(negOne) == 0 {
		return nil, fmt.Errorf("x25519 undefined for this public key")
	}

	// p = 2^255-19
	//
	// Equivalent to:
	// two := big.NewInt(2)
	// exp := big.NewInt(255)
	// p := new(big.Int).Exp(two, exp, nil)
	// p.Sub(p, big.NewInt(19))
	//
	p := new(big.Int).SetBytes([]byte{
		0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed,
	})

	onePlusY := new(big.Int).Add(one, y)
	oneMinusY := new(big.Int).Sub(one, y)
	oneMinusYInv := new(big.Int).ModInverse(oneMinusY, p)
	u := new(big.Int).Mul(onePlusY, oneMinusYInv)
	u.Mod(u, p)

	// make sure we get 32 bytes, pad if necessary
	uBytes := u.Bytes()
	res := make([]byte, PublicKeyBytesSize)
	copy(res[PublicKeyBytesSize-len(uBytes):], uBytes)

	// x25519 are little-endian, but big.Int gives us big-endian.
	// See https://www.ietf.org/rfc/rfc7748.txt
	return PublicKeyFromBytes(reverseBytes(res))
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
	ecdhPub := pub.(*ecdh.PublicKey)
	return (*PublicKey)(ecdhPub), nil
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
		return (*ecdh.PublicKey)(p).Equal((*ecdh.PublicKey)(other))
	}
	return false
}

func (p *PublicKey) ToBytes() []byte {
	return (*ecdh.PublicKey)(p).Bytes()
}

func (p *PublicKey) ToPublicKeyMultibase() string {
	return helpers.PublicKeyMultibaseEncode(MultibaseCode, (*ecdh.PublicKey)(p).Bytes())
}

func (p *PublicKey) ToX509DER() []byte {
	res, _ := x509.MarshalPKIXPublicKey((*ecdh.PublicKey)(p))
	return res
}

func (p *PublicKey) ToX509PEM() string {
	der := p.ToX509DER()
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  pemPubBlockType,
		Bytes: der,
	}))
}

func reverseBytes(b []byte) []byte {
	r := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		r[i] = b[len(b)-1-i]
	}
	return r
}
