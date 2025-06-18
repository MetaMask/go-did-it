package x25519

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/INFURA/go-did/verifications/ed25519"
	helpers "github.com/INFURA/go-did/verifications/internal"
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

	MultibaseCode = uint64(0xec)
)

func GenerateKeyPair() (PublicKey, PrivateKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv.Public().(PublicKey), priv, nil
}

// PublicKeyFromBytes converts a serialized public key to a PublicKey.
// This compact serialization format is the raw key material, without metadata or structure.
// It errors if the slice is not the right size.
func PublicKeyFromBytes(b []byte) (PublicKey, error) {
	return ecdh.X25519().NewPublicKey(b)
}

// PublicKeyToBytes converts a public key to a byte slice.
// This compact serialization format is the raw key material, without metadata or structure.
func PublicKeyToBytes(pub PublicKey) []byte {
	return pub.Bytes()
}

// PublicKeyFromEd25519 converts an ed25519 public key to a x25519 public key.
// It errors if the slice is not the right size.
//
// This function is based on the algorithm described in https://datatracker.ietf.org/doc/html/draft-ietf-core-oscore-groupcomm#name-curve25519
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

	// ed25519 are little-endian, but big.Int expects big-endian
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

	// x25519 are little-endian, but big.Int gives us big-endian.
	// See https://www.ietf.org/rfc/rfc7748.txt
	return ecdh.X25519().NewPublicKey(reverseBytes(res))
}

// PublicKeyFromMultibase decodes the public key from its Multibase form
func PublicKeyFromMultibase(multibase string) (PublicKey, error) {
	code, bytes, err := helpers.MultibaseDecode(multibase)
	if err != nil {
		return nil, err
	}
	if code != MultibaseCode {
		return nil, fmt.Errorf("invalid code")
	}
	return PublicKeyFromBytes(bytes)
}

// PublicKeyToMultibase encodes the public key in a suitable way for publicKeyMultibase
func PublicKeyToMultibase(pub PublicKey) string {
	return helpers.MultibaseEncode(MultibaseCode, pub.Bytes())
}

// PublicKeyFromX509DER decodes an X.509 DER (binary) encoded public key.
func PublicKeyFromX509DER(bytes []byte) (PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(bytes)
	if err != nil {
		return nil, err
	}
	return pub.(PublicKey), nil
}

// PublicKeyToX509DER encodes the public key into the X.509 DER (binary) format.
func PublicKeyToX509DER(pub PublicKey) []byte {
	res, _ := x509.MarshalPKIXPublicKey(pub)
	return res
}

const pemPubBlockType = "PUBLIC KEY"

// PublicKeyFromX509PEM decodes an X.509 PEM (string) encoded public key.
func PublicKeyFromX509PEM(str string) (PublicKey, error) {
	block, _ := pem.Decode([]byte(str))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != pemPubBlockType {
		return nil, fmt.Errorf("incorrect PEM block type")
	}
	return PublicKeyFromX509DER(block.Bytes)
}

// PublicKeyToX509PEM encodes the public key into the X.509 PEM (binary) format.
func PublicKeyToX509PEM(pub PublicKey) string {
	der := PublicKeyToX509DER(pub)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  pemPubBlockType,
		Bytes: der,
	}))
}

// PrivateKeyFromBytes converts a serialized private key to a PrivateKey.
// This compact serialization format is the raw key material, without metadata or structure.
// It errors if len(privateKey) is not [PrivateKeySize].
func PrivateKeyFromBytes(b []byte) (PrivateKey, error) {
	// this already check the size of b
	return ecdh.X25519().NewPrivateKey(b)
}

// PrivateKeyToBytes converts a private key to a byte slice.
// This compact serialization format is the raw key material, without metadata or structure.
func PrivateKeyToBytes(priv PrivateKey) []byte {
	return priv.Bytes()
}

// PrivateKeyFromEd25519 converts an ed25519 private key to a x25519 private key.
// It errors if the slice is not the right size.
//
// This function is based on the algorithm described in https://datatracker.ietf.org/doc/html/draft-ietf-core-oscore-groupcomm#name-curve25519
func PrivateKeyFromEd25519(priv ed25519.PrivateKey) (PrivateKey, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key size")
	}

	// get the 32-byte seed (first half of the private key)
	seed := priv.Seed()

	h := sha512.Sum512(seed)

	// clamp as per the X25519 spec
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64

	return ecdh.X25519().NewPrivateKey(h[:32])
}

// PrivateKeyFromPKCS8DER decodes a PKCS#8 DER (binary) encoded private key.
func PrivateKeyFromPKCS8DER(bytes []byte) (PrivateKey, error) {
	priv, err := x509.ParsePKCS8PrivateKey(bytes)
	if err != nil {
		return nil, err
	}
	return priv.(PrivateKey), nil
}

// PrivateKeyToPKCS8DER encodes the private key into the PKCS#8 DER (binary) format.
func PrivateKeyToPKCS8DER(priv PrivateKey) []byte {
	res, _ := x509.MarshalPKCS8PrivateKey(priv)
	return res
}

const pemPrivBlockType = "PRIVATE KEY"

// PrivateKeyFromPKCS8PEM decodes an PKCS#8 PEM (string) encoded private key.
func PrivateKeyFromPKCS8PEM(str string) (PrivateKey, error) {
	block, _ := pem.Decode([]byte(str))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != pemPrivBlockType {
		return nil, fmt.Errorf("incorrect PEM block type")
	}
	return PrivateKeyFromPKCS8DER(block.Bytes)
}

// PrivateKeyToPKCS8PEM encodes the private key into the PKCS#8 PEM (binary) format.
func PrivateKeyToPKCS8PEM(priv PrivateKey) string {
	der := PrivateKeyToPKCS8DER(priv)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  pemPrivBlockType,
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
