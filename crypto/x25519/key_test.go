package x25519

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MetaMask/go-did-it/crypto/_testsuite"
	"github.com/MetaMask/go-did-it/crypto/ed25519"
	"github.com/MetaMask/go-did-it/crypto/x25519/testvectors"
)

var harness = testsuite.TestHarness[*PublicKey, *PrivateKey]{
	Name:                            "x25519",
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
	SignatureBytesSize:              -1,
}

func TestSuite(t *testing.T) {
	testsuite.TestSuite(t, harness)
}

func BenchmarkSuite(b *testing.B) {
	testsuite.BenchSuite(b, harness)
}

func TestWycheproofKeyExchange(t *testing.T) {
	all, err := testvectors.Load()
	require.NoError(t, err)

	for _, v := range all {
		t.Run(fmt.Sprintf("%d-%s", v.TcId, v.Comment), func(t *testing.T) {
			pubBytes, err := hex.DecodeString(v.Public)
			require.NoError(t, err)
			privBytes, err := hex.DecodeString(v.Private)
			require.NoError(t, err)

			pub, err := PublicKeyFromBytes(pubBytes)
			require.NoError(t, err)
			priv, err := PrivateKeyFromBytes(privBytes)
			require.NoError(t, err)

			shared, err := priv.KeyExchange(pub)

			switch v.Result {
			case "valid":
				require.NoError(t, err, "tcId=%d: valid ECDH must succeed", v.TcId)
				want, _ := hex.DecodeString(v.Shared)
				require.Equal(t, want, shared, "tcId=%d: shared secret mismatch", v.TcId)
			case "acceptable":
				// Low-order points, twist points, etc. — may succeed or fail.
				// If it succeeded, the output must match.
				if err == nil {
					want, _ := hex.DecodeString(v.Shared)
					require.Equal(t, want, shared, "tcId=%d: shared secret mismatch", v.TcId)
				}
			}
		})
	}
}

func TestEd25519ToX25519(t *testing.T) {
	// Known pubkey ed25519 --> x25519
	for _, tc := range []struct {
		pubEdMultibase string
		pubXMultibase  string
	}{
		{
			// From https://w3c-ccg.github.io/did-key-spec/#ed25519-with-x25519
			pubEdMultibase: "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			pubXMultibase:  "z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p",
		},
	} {
		t.Run(tc.pubEdMultibase, func(t *testing.T) {
			pubEd, err := ed25519.PublicKeyFromPublicKeyMultibase(tc.pubEdMultibase)
			require.NoError(t, err)
			pubX, err := PublicKeyFromEd25519(pubEd)
			require.NoError(t, err)
			require.Equal(t, tc.pubXMultibase, pubX.ToPublicKeyMultibase())
		})
	}

	// Check that ed25519 --> x25519 match for pubkeys and privkeys
	t.Run("ed25519 --> x25519 priv+pub are matching", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			pubEd, privEd, err := ed25519.GenerateKeyPair()
			require.NoError(t, err)

			pubX, err := PublicKeyFromEd25519(pubEd)
			require.NoError(t, err)
			privX, err := PrivateKeyFromEd25519(privEd)
			require.NoError(t, err)

			require.True(t, pubX.Equal(privX.Public()))
		}
	})
}
