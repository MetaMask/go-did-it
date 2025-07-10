package didkey_test

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ucan-wg/go-did-it"
	"github.com/ucan-wg/go-did-it/crypto/ed25519"
	didkey "github.com/ucan-wg/go-did-it/verifiers/did-key"
)

func ExampleGenerateKeyPair() {
	// Generate a key pair
	pub, priv, err := ed25519.GenerateKeyPair()
	handleErr(err)
	fmt.Println("Public key:", pub.ToPublicKeyMultibase())
	fmt.Println("Private key:", base64.StdEncoding.EncodeToString(priv.ToBytes()))

	// Make the associated did:key
	dk := didkey.FromPrivateKey(priv)
	fmt.Println("Did:", dk.String())

	// Produce a signature
	msg := []byte("message")
	sig, err := priv.SignToBytes(msg)
	handleErr(err)
	fmt.Println("Signature:", base64.StdEncoding.EncodeToString(sig))

	// Resolve the DID and verify a signature
	doc, err := dk.Document()
	handleErr(err)
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

func TestFromPublicKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKeyPair()
	require.NoError(t, err)
	dk := didkey.FromPublicKey(pub)
	require.Equal(t, "did:key:"+pub.ToPublicKeyMultibase(), dk.String())
	doc, err := dk.Document()
	require.NoError(t, err)
	require.NotEmpty(t, doc)
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

func handleErr(err error) {
	if err != nil {
		panic(err)
	}
}
