package ed25519

import (
	"testing"

	"github.com/INFURA/go-did/crypto/internal"
)

var harness = helpers.TestHarness[PublicKey, PrivateKey]{
	Name:                            "ed25519",
	GenerateKeyPair:                 GenerateKeyPair,
	PublicKeyFromBytes:              PublicKeyFromBytes,
	PublicKeyFromPublicKeyMultibase: PublicKeyFromPublicKeyMultibase,
	PublicKeyFromX509DER:            PublicKeyFromX509DER,
	PublicKeyFromX509PEM:            PublicKeyFromX509PEM,
	PrivateKeyFromBytes:             PrivateKeyFromBytes,
	PrivateKeyFromPKCS8DER:          PrivateKeyFromPKCS8DER,
	PrivateKeyFromPKCS8PEM:          PrivateKeyFromPKCS8PEM,
	MultibaseCode:                   MultibaseCode,
	PublicKeySize:                   PublicKeySize,
	PrivateKeySize:                  PrivateKeySize,
	SignatureSize:                   SignatureSize,
}

func TestSuite(t *testing.T) {
	helpers.TestSuite(t, harness)
}

func BenchmarkSuite(b *testing.B) {
	helpers.BenchSuite(b, harness)
}
