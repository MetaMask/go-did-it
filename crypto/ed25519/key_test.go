package ed25519

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/_testsuite"
	"github.com/MetaMask/go-did-it/crypto/ed25519/testvectors"
)

var harness = testsuite.TestHarness[PublicKey, PrivateKey]{
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
	DefaultHash:                     crypto.SHA512,
	OtherHashes:                     nil,
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

func TestWycheproofVerifyBytes(t *testing.T) {
	all, err := testvectors.Load()
	require.NoError(t, err)

	for _, v := range all {
		t.Run(fmt.Sprintf("%d-%s", v.TcId, v.Comment), func(t *testing.T) {
			pk, err := hex.DecodeString(v.PK)
			require.NoError(t, err)
			pub, err := PublicKeyFromBytes(pk)
			require.NoError(t, err)

			msg, _ := hex.DecodeString(v.Msg)
			sig, _ := hex.DecodeString(v.Sig)

			got := pub.VerifyBytes(msg, sig)

			switch v.Result {
			case "valid":
				require.True(t, got, "tcId=%d: expected valid signature to verify", v.TcId)
			case "invalid":
				require.False(t, got, "tcId=%d: expected invalid signature to be rejected", v.TcId)
			}
			// "acceptable" — implementation-defined; just check for no panic
		})
	}
}
