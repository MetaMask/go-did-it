package ed25519_test

import (
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

func TestMultibaseRoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKeyPair()
	require.NoError(t, err)

	mb := ed25519.PublicKeyToMultibase(pub)
	rt, err := ed25519.PublicKeyFromMultibase(mb)
	require.NoError(t, err)
	require.Equal(t, pub, rt)
}
