package didkey_test

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/INFURA/go-did"
	didkey "github.com/INFURA/go-did/methods/did-key"
	"github.com/INFURA/go-did/verifications/ed25519"
)

func ExampleGenerateKeyPair() {
	// Generate a key pair
	pub, priv, err := ed25519.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	fmt.Println("Public key:", ed25519.PublicKeyToMultibase(pub))
	fmt.Println("Private key:", base64.StdEncoding.EncodeToString(priv))

	// Make the associated did:key
	dk, err := didkey.FromPrivateKey(priv)
	if err != nil {
		panic(err)
	}
	fmt.Println("Did:", dk.String())

	// Produce a signature
	msg := []byte("message")
	sig := ed25519.Sign(priv, msg)
	fmt.Println("Signature:", base64.StdEncoding.EncodeToString(sig))

	// Resolve the DID and verify a signature
	doc, err := dk.Document()
	if err != nil {
		panic(err)
	}
	ok, _ := did.TryAllVerify(doc.Authentication(), msg, sig)
	fmt.Println("Signature verified:", ok)
}

func TestParseDIDKey(t *testing.T) {
	str := "did:key:z6Mkod5Jr3yd5SC7UDueqK4dAAw5xYJYjksy722tA9Boxc4z"
	d, err := did.Parse(str)
	require.NoError(t, err)
	require.Equal(t, str, d.String())
}

func TestMustParseDIDKey(t *testing.T) {
	str := "did:key:z6Mkod5Jr3yd5SC7UDueqK4dAAw5xYJYjksy722tA9Boxc4z"
	require.NotPanics(t, func() {
		d := did.MustParse(str)
		require.Equal(t, str, d.String())
	})
	str = "did:key:z7Mkod5Jr3yd5SC7UDueqK4dAAw5xYJYjksy722tA9Boxc4z"
	require.Panics(t, func() {
		did.MustParse(str)
	})
}

func TestEquivalence(t *testing.T) {
	did0A, err := did.Parse("did:key:z6Mkod5Jr3yd5SC7UDueqK4dAAw5xYJYjksy722tA9Boxc4z")
	require.NoError(t, err)
	did0B, err := did.Parse("did:key:z6Mkod5Jr3yd5SC7UDueqK4dAAw5xYJYjksy722tA9Boxc4z")
	require.NoError(t, err)
	did1, err := did.Parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
	require.NoError(t, err)

	require.True(t, did0A.Equal(did0B))
	require.False(t, did0A.Equal(did1))
}
