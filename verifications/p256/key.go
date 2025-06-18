package p256

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"

	helpers "github.com/INFURA/go-did/verifications/internal"
)

type PublicKey = *ecdsa.PublicKey
type PrivateKey = *ecdsa.PrivateKey

const (
	// TODO
	PublicKeySize  = 33
	PrivateKeySize = 32
	SignatureSize  = 123456

	MultibaseCode = uint64(0x1200)
)

func GenerateKeyPair() (PublicKey, PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv.Public().(PublicKey), priv, nil
}

// PublicKeyFromBytes converts a serialized public key to a PublicKey.
// This compact serialization format is the raw key material, without metadata or structure.
// It errors if the slice is not the right size.
func PublicKeyFromBytes(b []byte) (PublicKey, error) {
	if len(b) != PublicKeySize {
		return nil, fmt.Errorf("invalid P-256 public key size")
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), b)
	if x == nil {
		return nil, fmt.Errorf("invalid P-256 public key")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil

	// if len(b) != PublicKeySize {
	// 	return nil, fmt.Errorf("invalid P-256 public key size")
	// }
	// x := new(big.Int).SetBytes(b[:PublicKeySize/2])
	// y := new(big.Int).SetBytes(b[PublicKeySize/2:])
	// return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// PublicKeyToBytes converts a public key to a byte slice.
// This compact serialization format is the raw key material, without metadata or structure.
func PublicKeyToBytes(pub PublicKey) []byte {
	return elliptic.MarshalCompressed(elliptic.P256(), pub.X, pub.Y)

	// // fixed size buffer that can get allocated on the caller's stack after inlining.
	// var buf [PublicKeySize]byte
	// pub.X.FillBytes(buf[:PublicKeySize/2])
	// pub.Y.FillBytes(buf[PublicKeySize/2:])
	// return buf[:]
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
	bytes := elliptic.MarshalCompressed(elliptic.P256(), pub.X, pub.Y)
	return helpers.MultibaseEncode(MultibaseCode, bytes)
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

// PrivateKeyFromBytes converts a serialized public key to a PrivateKey.
// This compact serialization format is the raw key material, without metadata or structure.
// It errors if the slice is not the right size.
func PrivateKeyFromBytes(b []byte) (PrivateKey, error) {
	if len(b) != PrivateKeySize {
		return nil, fmt.Errorf("invalid P-256 private key size")
	}

	res := &ecdsa.PrivateKey{
		D:         new(big.Int).SetBytes(b),
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()},
	}

	// recompute the public key
	res.PublicKey.X, res.PublicKey.Y = res.PublicKey.Curve.ScalarBaseMult(b)

	return res, nil
}

// PrivateKeyToBytes converts a private key to a byte slice.
// This compact serialization format is the raw key material, without metadata or structure.
func PrivateKeyToBytes(priv PrivateKey) []byte {
	// fixed size buffer that can get allocated on the caller's stack after inlining.
	var buf [PrivateKeySize]byte
	priv.D.FillBytes(buf[:])
	return buf[:]
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
