package bip340

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	testsuite "github.com/MetaMask/go-did-it/crypto/_testsuite"
	"github.com/MetaMask/go-did-it/crypto/bip340/testvectors"
)

var harness = testsuite.TestHarness[*PublicKey, *PrivateKey]{
	Name:                            "secp256k1-bip340",
	GenerateKeyPair:                 GenerateKeyPair,
	PublicKeyFromBytes:              PublicKeyFromBytes,
	PublicKeyFromPublicKeyMultibase: PublicKeyFromPublicKeyMultibase,
	PrivateKeyFromBytes:             PrivateKeyFromBytes,
	MultibaseCode:                   MultibaseCode,
	DefaultHash:                     0, // BIP-340 passes messages raw to its internal tagged hashes; no pre-hashing.
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

func TestBIP340Vectors(t *testing.T) {
	vectors, err := testvectors.Load()
	require.NoError(t, err)

	for _, v := range vectors {
		t.Run(vectorName(v), func(t *testing.T) {
			// Verification via public API.
			pub, err := PublicKeyFromBytes(v.PublicKey)
			if err != nil {
				require.False(t, v.Valid, "unexpected parse error: %v", err)
				return
			}

			got := pub.VerifyBytes(v.Message, v.Signature)
			require.Equal(t, v.Valid, got, "verification mismatch")

			// Signing (only when secret key and aux_rand are provided).
			if v.SecretKey == nil {
				return
			}

			priv, err := PrivateKeyFromBytes(v.SecretKey)
			require.NoError(t, err, "failed to parse private key")

			// Inject the known aux_rand for deterministic comparison against the vector.
			gotSig, err := bip340Sign(&priv.k.Key, priv.k.PubKey(), v.Message, v.AuxRand)
			require.NoError(t, err, "signing failed")
			require.Equal(t, v.Signature, gotSig, "signature mismatch")
		})
	}
}

func vectorName(v testvectors.Vector) string {
	if v.Comment != "" {
		return fmt.Sprintf("%d-%s", v.Index, v.Comment)
	}
	return fmt.Sprintf("%d", v.Index)
}
