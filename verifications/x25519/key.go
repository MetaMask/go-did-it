package x25519

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"math/big"

	mbase "github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"

	"github.com/INFURA/go-did/verifications/ed25519"
)

type PublicKey = *ecdh.PublicKey
type PrivateKey = *ecdh.PrivateKey

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = 32
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 32
	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = 32
)

func GenerateKeyPair() (PublicKey, PrivateKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv.Public().(PublicKey), priv, nil
}

// PublicKeyFromBytes convert a serialized public key to a PublicKey.
// It errors if the slice is not the right size.
func PublicKeyFromBytes(b []byte) (PublicKey, error) {
	return ecdh.X25519().NewPublicKey(b)
}

func PublicKeyFromEd25519(pub ed25519.PublicKey) (PublicKey, error) {
	// Conversion formula is u = (1 + y) / (1 - y) (mod p)
	// See https://datatracker.ietf.org/doc/html/draft-ietf-core-oscore-groupcomm#name-ecdh-with-montgomery-coordi

	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key size")
	}

	// Make a copy and clear the sign bit (MSB of last byte)
	// This is because ed25519 serialize as bytes with 255 bit for Y, and one bit for the sign.
	// We only want Y, and the sign is irrelevant for the conversion.
	pubCopy := make([]byte, ed25519.PublicKeySize)
	copy(pubCopy, pub)
	pubCopy[ed25519.PublicKeySize-1] &= 0x7F

	// ed25519 are little-endian, but big.Int expect big-endian
	// See https://www.rfc-editor.org/rfc/rfc8032
	y := new(big.Int).SetBytes(reverseBytes(pubCopy))
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
	res := make([]byte, PublicKeySize)
	copy(res[PublicKeySize-len(uBytes):], uBytes)

	// x25519 are little-endian, but big.Int give us big-endian.
	// See https://www.ietf.org/rfc/rfc7748.txt
	return ecdh.X25519().NewPublicKey(reverseBytes(res))
}

// PublicKeyFromMultibase decodes the public key from its Multibase form
func PublicKeyFromMultibase(multibase string) (PublicKey, error) {
	baseCodec, bytes, err := mbase.Decode(multibase)
	if err != nil {
		return nil, err
	}
	// the specification enforces that encoding
	if baseCodec != mbase.Base58BTC {
		return nil, fmt.Errorf("not Base58BTC encoded")
	}
	code, read, err := varint.FromUvarint(bytes)
	if err != nil {
		return nil, err
	}
	if code != MultibaseCode {
		return nil, fmt.Errorf("invalid code")
	}
	if read != 2 {
		return nil, fmt.Errorf("unexpected multibase")
	}
	return ecdh.X25519().NewPublicKey(bytes[read:])
}

// PublicKeyToMultibase encodes the public key in a suitable way for publicKeyMultibase
func PublicKeyToMultibase(pub PublicKey) string {
	// can only fail with an invalid encoding, but it's hardcoded
	bytes, _ := mbase.Encode(mbase.Base58BTC, append(varint.ToUvarint(MultibaseCode), pub.Bytes()...))
	return bytes
}

// PrivateKeyFromBytes convert a serialized public key to a PrivateKey.
// It errors if len(privateKey) is not [PrivateKeySize].
func PrivateKeyFromBytes(b []byte) (PrivateKey, error) {
	return ecdh.X25519().NewPrivateKey(b)
}

func reverseBytes(b []byte) []byte {
	r := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		r[i] = b[len(b)-1-i]
	}
	return r
}
