package x25519

// TODO: use ecdh.PublicKey instead of defining a custom type below?

// type PublicKey ecdh.PublicKey
//
// func (p PublicKey) Equal(x crypto.PublicKey) bool {
// 	// TODO implement me
// 	panic("implement me")
// }
//
// type PrivateKey ecdh.PrivateKey
//
// func (p *PrivateKey) Public() crypto.PublicKey {
// 	key := p.(ecdh.PrivateKey)
// 	return key.Public()
// }
//
// func (p *PrivateKey) Equal(x crypto.PrivateKey) bool {
// 	// TODO implement me
// 	panic("implement me")
// }
//
// func GenerateKeyPair() (PublicKey, PrivateKey, error) {
// 	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
// 	if err != nil {
// 		return nil, nil, err
// 	}
// 	return priv.Public().(PublicKey), priv, nil
// }
//
// // PublicKeyToMultibase encodes the public key in a suitable way for publicKeyMultibase
// func PublicKeyToMultibase(pub PublicKey) string {
// 	// can only fail with an invalid encoding, but it's hardcoded
// 	bytes, _ := mbase.Encode(mbase.Base58BTC, append(varint.ToUvarint(MultibaseCode), pub.Bytes()...))
// 	return bytes
// }
//
// // MultibaseToPublicKey decodes the public key from its publicKeyMultibase form
// func MultibaseToPublicKey(multibase string) (PublicKey, error) {
// 	baseCodec, bytes, err := mbase.Decode(multibase)
// 	if err != nil {
// 		return nil, err
// 	}
// 	// the specification enforces that encoding
// 	if baseCodec != mbase.Base58BTC {
// 		return nil, fmt.Errorf("not Base58BTC encoded")
// 	}
// 	code, read, err := varint.FromUvarint(bytes)
// 	if err != nil {
// 		return nil, err
// 	}
// 	if code != MultibaseCode {
// 		return nil, fmt.Errorf("invalid code")
// 	}
// 	if read != 2 {
// 		return nil, fmt.Errorf("unexpected multibase")
// 	}
// 	if len(bytes)-read != ed25519.PublicKeySize {
// 		return nil, fmt.Errorf("invalid ed25519 public key size")
// 	}
// 	return bytes[read:], nil
// }

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/curve25519"

	"github.com/INFURA/go-did/verifications/ed25519"
)

// This mirrors ed25519's structure for private/public "keys". We
// require dedicated types for these as they drive
// serialization/deserialization logic, as well as encryption types.
//
// Note that with the x25519 scheme, the private key is a sequence of
// 32 bytes, while the public key is the result of X25519(private,
// basepoint).
//
// Portions of this file are from Go's ed25519.go, which is
// Copyright 2016 The Go Authors. All rights reserved.

// Originally taken from github.com/lestrrat-go/jwx/v2/x25519.

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = 32
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 64
	// SeedSize is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
	SeedSize = 32
)

// PublicKey is the type of X25519 public keys
type PublicKey []byte

// NewKeyFromSeed calculates a private key from a seed. It will return
// an error if len(seed) is not SeedSize. This function is provided
// for interoperability with RFC 7748. RFC 7748's private keys
// correspond to seeds in this package.
func NewKeyFromSeed(seed []byte) (PrivateKey, error) {
	privateKey := make([]byte, PrivateKeySize)
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("unexpected seed size: %d", len(seed))
	}
	copy(privateKey, seed)
	public, err := curve25519.X25519(seed, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf(`failed to compute public key: %w`, err)
	}
	copy(privateKey[SeedSize:], public)

	return privateKey, nil
}

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey() (PublicKey, PrivateKey, error) {
	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, nil, err
	}

	privateKey, err := NewKeyFromSeed(seed)
	if err != nil {
		return nil, nil, err
	}
	publicKey := make([]byte, PublicKeySize)
	copy(publicKey, privateKey[SeedSize:])

	return publicKey, privateKey, nil
}

// Any methods implemented on PublicKey might need to also be implemented on
// PrivateKey, as the latter embeds the former and will expose its methods.

// Equal reports whether pub and x have the same value.
func (pub PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(PublicKey)
	if !ok {
		return false
	}
	return bytes.Equal(pub, xx)
}

// PrivateKey is the type of X25519 private key
type PrivateKey []byte

// Public returns the PublicKey corresponding to priv.
func (priv PrivateKey) Public() crypto.PublicKey {
	publicKey := make([]byte, PublicKeySize)
	copy(publicKey, priv[SeedSize:])
	return PublicKey(publicKey)
}

// Equal reports whether priv and x have the same value.
func (priv PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(PrivateKey)
	if !ok {
		return false
	}
	return bytes.Equal(priv, xx)
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
	return reverseBytes(res), nil
}

func reverseBytes(b []byte) []byte {
	r := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		r[i] = b[len(b)-1-i]
	}
	return r
}
