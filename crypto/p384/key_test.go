package p384

import (
	"crypto/elliptic"
	"testing"

	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/_testsuite"
)

var harness = testsuite.TestHarness[*PublicKey, *PrivateKey]{
	Name:                            "p384",
	GenerateKeyPair:                 GenerateKeyPair,
	PublicKeyFromBytes:              PublicKeyFromBytes,
	PublicKeyFromPublicKeyMultibase: PublicKeyFromPublicKeyMultibase,
	PublicKeyFromX509DER:            PublicKeyFromX509DER,
	PublicKeyFromX509PEM:            PublicKeyFromX509PEM,
	PrivateKeyFromBytes:             PrivateKeyFromBytes,
	PrivateKeyFromPKCS8DER:          PrivateKeyFromPKCS8DER,
	PrivateKeyFromPKCS8PEM:          PrivateKeyFromPKCS8PEM,
	MultibaseCode:                   MultibaseCode,
	DefaultHash:                     crypto.SHA384,
	OtherHashes:                     []crypto.Hash{crypto.SHA256, crypto.SHA512},
	SupportsPreHashed:               true,
	PublicKeyBytesSize:              PublicKeyBytesSize,
	PrivateKeyBytesSize:             PrivateKeyBytesSize,
	SignatureBytesSize:              SignatureBytesSize,
}

func TestSuite(t *testing.T) {
	testsuite.TestSuite(t, harness)
}

func TestEcdsaLowS(t *testing.T) {
	testsuite.TestEcdsaLowSSuite(t, harness, elliptic.P384().Params().N)
}

func BenchmarkSuite(b *testing.B) {
	testsuite.BenchSuite(b, harness)
}
