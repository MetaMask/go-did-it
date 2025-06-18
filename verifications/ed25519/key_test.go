package ed25519_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/INFURA/go-did/verifications/ed25519"
)

func TestGenerateKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKeyPair()
	require.NoError(t, err)
	require.NotNil(t, pub)
	require.NotNil(t, priv)
	require.True(t, pub.Equal(priv.Public()))
}

func TestBytesRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKeyPair()
	require.NoError(t, err)

	bytes := ed25519.PublicKeyToBytes(pub)
	fmt.Println("pub", len(bytes))
	rtPub, err := ed25519.PublicKeyFromBytes(bytes)
	require.NoError(t, err)
	require.True(t, pub.Equal(rtPub))

	bytes = ed25519.PrivateKeyToBytes(priv)
	fmt.Println("priv", len(bytes))
	rtPriv, err := ed25519.PrivateKeyFromBytes(bytes)
	require.NoError(t, err)
	require.True(t, priv.Equal(rtPriv))
}

func TestMultibaseRoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKeyPair()
	require.NoError(t, err)

	mb := ed25519.PublicKeyToMultibase(pub)
	rt, err := ed25519.PublicKeyFromMultibase(mb)
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

// func TestSignature(t *testing.T) {
// 	pub, priv, err := ed25519.GenerateKeyPair()
// 	require.NoError(t, err)
//
// 	sig := ed25519.Sign(priv, []byte("message"))
//
// }
