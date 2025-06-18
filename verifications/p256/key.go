package p256

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	helpers "github.com/INFURA/go-did/verifications/internal"
)

type PublicKey = *ecdsa.PublicKey
type PrivateKey = *ecdsa.PrivateKey

const (
	// TODO
	PublicKeySize  = 123456
	PrivateKeySize = 123456
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
}

// PublicKeyToBytes converts a public key to a byte slice.
func PublicKeyToBytes(pub PublicKey) (res []byte, err error) {
	defer func() {
		if rerr := recover(); rerr != nil {
			err = fmt.Errorf("recovered panic: %s", rerr)
			res = nil
		}
	}()
	return x509.MarshalPKIXPublicKey(pub)
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

// PrivateKeyFromBytes converts a serialized public key to a PrivateKey.
// It errors if the slice is not the right size.
func PrivateKeyFromBytes(b []byte) (PrivateKey, error) {
	if len(b) != PrivateKeySize {
		return nil, fmt.Errorf("invalid P-256 private key size")
	}
	// TODO

	return nil, nil
}
