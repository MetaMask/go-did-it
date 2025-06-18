package x25519_test

import (
	"crypto/ecdh"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/INFURA/go-did/verifications/ed25519"
	"github.com/INFURA/go-did/verifications/x25519"
)

func TestGenerateKey(t *testing.T) {
	pub, priv, err := x25519.GenerateKeyPair()
	require.NoError(t, err)
	require.NotNil(t, pub)
	require.NotNil(t, priv)
	require.Equal(t, ecdh.X25519(), pub.Curve())
	require.Equal(t, ecdh.X25519(), priv.Curve())
	require.True(t, pub.Equal(priv.Public()))
}

func TestBytesRoundTrip(t *testing.T) {
	pub, priv, err := x25519.GenerateKeyPair()
	require.NoError(t, err)

	bytes := x25519.PublicKeyToBytes(pub)
	fmt.Println("pub", len(bytes))
	rtPub, err := x25519.PublicKeyFromBytes(bytes)
	require.NoError(t, err)
	require.True(t, pub.Equal(rtPub))

	bytes = x25519.PrivateKeyToBytes(priv)
	fmt.Println("priv", len(bytes))
	rtPriv, err := x25519.PrivateKeyFromBytes(bytes)
	require.NoError(t, err)
	require.True(t, priv.Equal(rtPriv))
}

func TestMultibaseRoundTrip(t *testing.T) {
	pub, _, err := x25519.GenerateKeyPair()
	require.NoError(t, err)

	mb := x25519.PublicKeyToMultibase(pub)
	rt, err := x25519.PublicKeyFromMultibase(mb)
	require.NoError(t, err)
	require.Equal(t, pub, rt)
}

func TestPublicKeyX509RoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKeyPair()
	require.NoError(t, err)

	der := ed25519.PublicKeyToX509DER(pub)
	fmt.Println("der", len(der))
	rt, err := ed25519.PublicKeyFromX509DER(der)
	require.NoError(t, err)
	require.True(t, pub.Equal(rt))

	pem := ed25519.PublicKeyToX509PEM(pub)
	fmt.Println("pem", len(pem))
	rt, err = ed25519.PublicKeyFromX509PEM(pem)
	require.NoError(t, err)
	require.True(t, pub.Equal(rt))
}

func TestPrivateKeyPKCS8RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKeyPair()
	require.NoError(t, err)

	der := ed25519.PrivateKeyToPKCS8DER(priv)
	fmt.Println("der", len(der))
	rt, err := ed25519.PrivateKeyFromPKCS8DER(der)
	require.NoError(t, err)
	require.True(t, priv.Equal(rt))
	require.True(t, pub.Equal(rt.Public()))

	pem := ed25519.PrivateKeyToPKCS8PEM(priv)
	fmt.Println("pem", len(pem))
	rt, err = ed25519.PrivateKeyFromPKCS8PEM(pem)
	require.NoError(t, err)
	require.True(t, priv.Equal(rt))
	require.True(t, pub.Equal(rt.Public()))
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
			pubEd, err := ed25519.PublicKeyFromMultibase(tc.pubEdMultibase)
			require.NoError(t, err)
			pubX, err := x25519.PublicKeyFromEd25519(pubEd)
			require.NoError(t, err)
			require.Equal(t, tc.pubXMultibase, x25519.PublicKeyToMultibase(pubX))
		})
	}

	// Check that ed25519 --> x25519 match for pubkeys and privkeys
	t.Run("ed25519 --> x25519 priv+pub are matching", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			pubEd, privEd, err := ed25519.GenerateKeyPair()
			require.NoError(t, err)

			pubX, err := x25519.PublicKeyFromEd25519(pubEd)
			require.NoError(t, err)
			privX, err := x25519.PrivateKeyFromEd25519(privEd)
			require.NoError(t, err)

			require.True(t, pubX.Equal(privX.PublicKey()))
		}
	})
}
