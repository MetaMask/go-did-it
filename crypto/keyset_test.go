package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/ed25519"
	"github.com/MetaMask/go-did-it/crypto/p256"
	"github.com/MetaMask/go-did-it/crypto/rsa"
)

func TestKeySet_RestrictsByType(t *testing.T) {
	edPub, _, err := ed25519.GenerateKeyPair()
	require.NoError(t, err)
	p256Pub, _, err := p256.GenerateKeyPair()
	require.NoError(t, err)

	// A KeySet that only allows Ed25519.
	ks := crypto.NewKeySet(ed25519.KeyType())

	got, err := ks.PublicKeyFromMultibase(edPub.ToPublicKeyMultibase())
	require.NoError(t, err)
	require.True(t, got.Equal(edPub))

	// P-256 is a valid key, but not in this KeySet: it must be rejected.
	_, err = ks.PublicKeyFromMultibase(p256Pub.ToPublicKeyMultibase())
	require.Error(t, err)

	// Widen the policy and it now decodes.
	ks.Register(p256.KeyType())
	got, err = ks.PublicKeyFromMultibase(p256Pub.ToPublicKeyMultibase())
	require.NoError(t, err)
	require.True(t, got.Equal(p256Pub))
}

func TestKeySet_RSASizePolicy(t *testing.T) {
	pub, _, err := rsa.GenerateKeyPair(2048)
	require.NoError(t, err)
	mb := pub.ToPublicKeyMultibase()

	// Sizes 3072 and 4096 allowed: a 2048 key is rejected purely on size.
	ks := crypto.NewKeySet(rsa.KeyType(3072, 4096))
	_, err = ks.PublicKeyFromMultibase(mb)
	require.Error(t, err)

	// Replace the RSA policy with one that includes 2048 and it decodes.
	ks.Register(rsa.KeyType(2048, 3072, 4096))
	got, err := ks.PublicKeyFromMultibase(mb)
	require.NoError(t, err)
	require.True(t, got.Equal(pub))
}
