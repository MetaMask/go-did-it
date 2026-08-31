package crypto_test

import (
	stdecdsa "crypto/ecdsa"
	stded25519 "crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/ed25519"
	"github.com/MetaMask/go-did-it/crypto/p256"
	"github.com/MetaMask/go-did-it/crypto/p384"
	"github.com/MetaMask/go-did-it/crypto/rsa"
)

func TestKeyPolicy_RestrictsByType(t *testing.T) {
	edPub, _, err := ed25519.GenerateKeyPair()
	require.NoError(t, err)
	p256Pub, _, err := p256.GenerateKeyPair()
	require.NoError(t, err)

	// A KeyPolicy that only allows Ed25519.
	kp := crypto.NewKeyPolicy(ed25519.KeyType())

	got, err := kp.PublicKeyFromMultibase(edPub.ToPublicKeyMultibase())
	require.NoError(t, err)
	require.True(t, got.Equal(edPub))

	// P-256 is a valid key, but not in this KeyPolicy: it must be rejected.
	_, err = kp.PublicKeyFromMultibase(p256Pub.ToPublicKeyMultibase())
	require.Error(t, err)

	// Widen the policy and it now decodes.
	kp.Register(p256.KeyType())
	got, err = kp.PublicKeyFromMultibase(p256Pub.ToPublicKeyMultibase())
	require.NoError(t, err)
	require.True(t, got.Equal(p256Pub))
}

func TestKeyPolicy_RSASizePolicy(t *testing.T) {
	pub, _, err := rsa.GenerateKeyPair(2048)
	require.NoError(t, err)
	mb := pub.ToPublicKeyMultibase()

	// Sizes 3072 and 4096 allowed: a 2048 key is rejected purely on size.
	kp := crypto.NewKeyPolicy(rsa.KeyType(3072, 4096))
	_, err = kp.PublicKeyFromMultibase(mb)
	require.ErrorIs(t, err, crypto.ErrKeyNotAccepted)

	// Replace the RSA policy with one that includes 2048 and it decodes.
	kp.Register(rsa.KeyType(2048, 3072, 4096))
	got, err := kp.PublicKeyFromMultibase(mb)
	require.NoError(t, err)
	require.True(t, got.Equal(pub))
}

func TestKeyPolicy_TypedErrors(t *testing.T) {
	edPub, _, err := ed25519.GenerateKeyPair()
	require.NoError(t, err)
	p256Pub, _, err := p256.GenerateKeyPair()
	require.NoError(t, err)

	// A KeyPolicy that only allows Ed25519.
	kp := crypto.NewKeyPolicy(ed25519.KeyType())

	tests := []struct {
		name      string
		multibase string
		wantErr   error
		notErr    error
	}{
		{
			name:      "valid key of an algorithm outside the policy",
			multibase: p256Pub.ToPublicKeyMultibase(),
			wantErr:   crypto.ErrKeyNotAccepted,
			notErr:    crypto.ErrInvalidKey,
		},
		{
			name:      "garbage multibase",
			multibase: "not-multibase",
			wantErr:   crypto.ErrInvalidKey,
			notErr:    crypto.ErrKeyNotAccepted,
		},
		{
			name:      "right algorithm, corrupted body",
			multibase: edPub.ToPublicKeyMultibase()[:10],
			wantErr:   crypto.ErrInvalidKey,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := kp.PublicKeyFromMultibase(tc.multibase)
			require.ErrorIs(t, err, tc.wantErr)
			if tc.notErr != nil {
				require.NotErrorIs(t, err, tc.notErr)
			}
		})
	}
}

// An empty KeyPolicy is the likely sign of a missing registration (DefaultKeyPolicy starts empty),
// so the rejection errors must say so.
func TestKeyPolicy_EmptySetHint(t *testing.T) {
	edPub, _, err := ed25519.GenerateKeyPair()
	require.NoError(t, err)

	kp := crypto.NewKeyPolicy()

	_, err = kp.PublicKeyFromMultibase(edPub.ToPublicKeyMultibase())
	require.ErrorIs(t, err, crypto.ErrKeyNotAccepted)
	require.ErrorContains(t, err, "the key policy is empty")

	_, err = kp.WrapPublicKey(stded25519.PublicKey(make([]byte, stded25519.PublicKeySize)))
	require.ErrorIs(t, err, crypto.ErrKeyNotAccepted)
	require.ErrorContains(t, err, "the key policy is empty")

	err = kp.CheckKey(edPub)
	require.ErrorIs(t, err, crypto.ErrKeyNotAccepted)
	require.ErrorContains(t, err, "the key policy is empty")
}

func TestKeyPolicy_WrapPublicKey(t *testing.T) {
	kp := crypto.NewKeyPolicy(ed25519.KeyType(), p256.KeyType(), p384.KeyType(), rsa.KeyType(3072, 4096))

	stdEdPub, _, err := stded25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	p256Priv, err := stdecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p384Priv, err := stdecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	p521Priv, err := stdecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	rsaPub, _, err := rsa.GenerateKeyPair(2048)
	require.NoError(t, err)

	tests := []struct {
		name     string
		key      any
		wantType crypto.PublicKey
		wantErr  error
	}{
		{name: "std ed25519", key: stdEdPub, wantType: ed25519.PublicKey{}},
		{name: "std ecdsa P-256", key: &p256Priv.PublicKey, wantType: &p256.PublicKey{}},
		{name: "std ecdsa P-384", key: &p384Priv.PublicKey, wantType: &p384.PublicKey{}},
		{name: "valid curve not in the key policy", key: &p521Priv.PublicKey, wantErr: crypto.ErrKeyNotAccepted},
		{name: "RSA outside the key policy size policy", key: rsaPub.Unwrap(), wantErr: crypto.ErrKeyNotAccepted},
		{name: "not a key at all", key: "not a key", wantErr: crypto.ErrKeyNotAccepted},
		// Malformed key data must report ErrInvalidKey, like PublicKeyFromBytes does, and not
		// be confused with a policy rejection.
		{name: "malformed ed25519", key: stded25519.PublicKey("too short"), wantErr: crypto.ErrInvalidKey},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := kp.WrapPublicKey(tc.key)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				// the two error kinds are mutually exclusive
				other := crypto.ErrInvalidKey
				if tc.wantErr == crypto.ErrInvalidKey {
					other = crypto.ErrKeyNotAccepted
				}
				require.NotErrorIs(t, err, other)
				return
			}
			require.NoError(t, err)
			require.IsType(t, tc.wantType, got)

			// the wrapped key round-trips through its multibase form
			back, err := kp.PublicKeyFromMultibase(got.ToPublicKeyMultibase())
			require.NoError(t, err)
			require.True(t, back.Equal(got))
		})
	}
}

func TestKeyPolicy_KeyTypes(t *testing.T) {
	kp := crypto.NewKeyPolicy(p256.KeyType(), ed25519.KeyType())

	kts := kp.KeyTypes()
	require.Len(t, kts, 2)
	// sorted by multicodec code: ed25519 (0xed) < p256 (0x1200)
	require.Equal(t, "Ed25519", kts[0].Name)
	require.Equal(t, "P-256", kts[1].Name)
}
