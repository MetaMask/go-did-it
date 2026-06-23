package p521

import (
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/_testsuite"
	"github.com/MetaMask/go-did-it/crypto/p256"
	"github.com/MetaMask/go-did-it/crypto/p384"
)

var harness = testsuite.TestHarness[*PublicKey, *PrivateKey]{
	Name:                            "p521",
	GenerateKeyPair:                 GenerateKeyPair,
	PublicKeyFromBytes:              PublicKeyFromBytes,
	PublicKeyFromPublicKeyMultibase: PublicKeyFromPublicKeyMultibase,
	PublicKeyFromX509DER:            PublicKeyFromX509DER,
	PublicKeyFromX509PEM:            PublicKeyFromX509PEM,
	PrivateKeyFromBytes:             PrivateKeyFromBytes,
	PrivateKeyFromPKCS8DER:          PrivateKeyFromPKCS8DER,
	PrivateKeyFromPKCS8PEM:          PrivateKeyFromPKCS8PEM,
	MultibaseCode:                   MultibaseCode,
	DefaultHash:                     crypto.SHA512,
	OtherHashes:                     []crypto.Hash{crypto.SHA384},
	SupportsPreHashed:               true,
	PublicKeyBytesSize:              PublicKeyBytesSize,
	PrivateKeyBytesSize:             PrivateKeyBytesSize,
	SignatureBytesSize:              SignatureBytesSize,
}

func TestSuite(t *testing.T) {
	testsuite.TestSuite(t, harness)
}

func TestEcdsaLowS(t *testing.T) {
	testsuite.TestEcdsaLowSSuite(t, harness, elliptic.P521().Params().N)
}

func BenchmarkSuite(b *testing.B) {
	testsuite.BenchSuite(b, harness)
}

func TestRejectForeignCurveX509AndPKCS8(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pubDER  func() []byte
		privDER func() []byte
	}{
		{
			name: "p256",
			pubDER: func() []byte {
				pub, _, err := p256.GenerateKeyPair()
				require.NoError(t, err)
				return pub.ToX509DER()
			},
			privDER: func() []byte {
				_, priv, err := p256.GenerateKeyPair()
				require.NoError(t, err)
				return priv.ToPKCS8DER()
			},
		},
		{
			name: "p384",
			pubDER: func() []byte {
				pub, _, err := p384.GenerateKeyPair()
				require.NoError(t, err)
				return pub.ToX509DER()
			},
			privDER: func() []byte {
				_, priv, err := p384.GenerateKeyPair()
				require.NoError(t, err)
				return priv.ToPKCS8DER()
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := PublicKeyFromX509DER(tc.pubDER())
			require.Error(t, err)

			_, err = PrivateKeyFromPKCS8DER(tc.privDER())
			require.Error(t, err)
		})
	}
}

func TestRejectInvalidPrivateScalars(t *testing.T) {
	// Zero is outside the valid scalar range [1, N-1].
	_, err := PrivateKeyFromBytes(make([]byte, PrivateKeyBytesSize))
	require.Error(t, err)

	// N is out of range; valid scalars are [1, N-1].
	_, err = PrivateKeyFromBytes(elliptic.P521().Params().N.FillBytes(make([]byte, PrivateKeyBytesSize)))
	require.Error(t, err)
}
