package p256

import (
	"testing"

	"github.com/INFURA/go-did/crypto/_testsuite"
)

var harness = testsuite.TestHarness[*PublicKey, *PrivateKey]{
	Name:                            "p256",
	GenerateKeyPair:                 GenerateKeyPair,
	PublicKeyFromBytes:              PublicKeyFromBytes,
	PublicKeyFromPublicKeyMultibase: PublicKeyFromPublicKeyMultibase,
	PublicKeyFromX509DER:            PublicKeyFromX509DER,
	PublicKeyFromX509PEM:            PublicKeyFromX509PEM,
	PrivateKeyFromBytes:             PrivateKeyFromBytes,
	PrivateKeyFromPKCS8DER:          PrivateKeyFromPKCS8DER,
	PrivateKeyFromPKCS8PEM:          PrivateKeyFromPKCS8PEM,
	MultibaseCode:                   MultibaseCode,
	PublicKeyBytesSize:              PublicKeyBytesSize,
	PrivateKeyBytesSize:             PrivateKeyBytesSize,
	SignatureBytesSize:              SignatureBytesSize,
}

func TestSuite(t *testing.T) {
	testsuite.TestSuite(t, harness)
}

func BenchmarkSuite(b *testing.B) {
	testsuite.BenchSuite(b, harness)
}
