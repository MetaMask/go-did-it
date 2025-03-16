package x25519_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/INFURA/go-did/verifications/x25519"
)

func TestGenerateKey(t *testing.T) {
	t.Run("x25519.GenerateKey()", func(t *testing.T) {
		_, _, err := x25519.GenerateKey()
		require.NoError(t, err, `x25519.GenerateKey should work`)
	})
	t.Run("x25519.NewKeyFromSeed(wrongSeedLength)", func(t *testing.T) {
		dummy := make([]byte, x25519.SeedSize-1)
		_, err := x25519.NewKeyFromSeed(dummy)
		require.Error(t, err, `wrong seed size should result in error`)
	})
}

func TestNewKeyFromSeed(t *testing.T) {
	// These test vectors are from RFC7748 Section 6.1
	const alicePrivHex = `77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a`
	const alicePubHex = `8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a`
	const bobPrivHex = `5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb`
	const bobPubHex = `de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f`

	alicePrivSeed, err := hex.DecodeString(alicePrivHex)
	require.NoError(t, err, `alice seed decoded`)
	alicePriv, err := x25519.NewKeyFromSeed(alicePrivSeed)
	require.NoError(t, err, `alice private key`)

	alicePub := alicePriv.Public().(x25519.PublicKey)
	require.Equal(t, hex.EncodeToString(alicePub), alicePubHex, `alice public key`)

	bobPrivSeed, err := hex.DecodeString(bobPrivHex)
	require.NoError(t, err, `bob seed decoded`)
	bobPriv, err := x25519.NewKeyFromSeed(bobPrivSeed)
	require.NoError(t, err, `bob private key`)

	bobPub := bobPriv.Public().(x25519.PublicKey)
	require.Equal(t, hex.EncodeToString(bobPub), bobPubHex, `bob public key`)

	require.True(t, bobPriv.Equal(bobPriv), `bobPriv should equal bobPriv`)
	require.True(t, bobPub.Equal(bobPub), `bobPub should equal bobPub`)
	require.False(t, bobPriv.Equal(bobPub), `bobPriv should NOT equal bobPub`)
	require.False(t, bobPub.Equal(bobPriv), `bobPub should NOT equal bobPriv`)
}
