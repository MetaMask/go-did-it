package p256_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/INFURA/go-did/verifications/p256"
)

func TestGenerateKey(t *testing.T) {
	pub, priv, err := p256.GenerateKeyPair()
	require.NoError(t, err)
	require.NotNil(t, pub)
	require.NotNil(t, priv)
	require.True(t, pub.Equal(priv.Public()))
}

func TestBytesRoundTrip(t *testing.T) {
	pub, priv, err := p256.GenerateKeyPair()
	require.NoError(t, err)

	bytes := p256.PublicKeyToBytes(pub)
	rtPub, err := p256.PublicKeyFromBytes(bytes)
	require.NoError(t, err)
	require.True(t, pub.Equal(rtPub))

	bytes = p256.PrivateKeyToBytes(priv)
	rtPriv, err := p256.PrivateKeyFromBytes(bytes)
	require.NoError(t, err)
	require.True(t, priv.Equal(rtPriv))
}

func TestPublicKeyX509RoundTrip(t *testing.T) {
	pub, _, err := p256.GenerateKeyPair()
	require.NoError(t, err)

	der := p256.PublicKeyToX509DER(pub)
	rt, err := p256.PublicKeyFromX509DER(der)
	require.NoError(t, err)
	require.True(t, pub.Equal(rt))

	pem := p256.PublicKeyToX509PEM(pub)
	rt, err = p256.PublicKeyFromX509PEM(pem)
	require.NoError(t, err)
	require.True(t, pub.Equal(rt))
}

func TestPrivateKeyPKCS8RoundTrip(t *testing.T) {
	pub, priv, err := p256.GenerateKeyPair()
	require.NoError(t, err)

	der := p256.PrivateKeyToPKCS8DER(priv)
	rt, err := p256.PrivateKeyFromPKCS8DER(der)
	require.NoError(t, err)
	require.True(t, priv.Equal(rt))
	require.True(t, pub.Equal(rt.Public()))

	pem := p256.PrivateKeyToPKCS8PEM(priv)
	rt, err = p256.PrivateKeyFromPKCS8PEM(pem)
	require.NoError(t, err)
	require.True(t, priv.Equal(rt))
	require.True(t, pub.Equal(rt.Public()))
}

func TestMultibaseRoundTrip(t *testing.T) {
	pub, _, err := p256.GenerateKeyPair()
	require.NoError(t, err)

	mb := p256.PublicKeyToMultibase(pub)
	rt, err := p256.PublicKeyFromMultibase(mb)
	require.NoError(t, err)
	require.Equal(t, pub, rt)
}
