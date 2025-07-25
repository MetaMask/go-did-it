package ed25519vm_test

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ucan-wg/go-did-it"
	"github.com/ucan-wg/go-did-it/crypto/ed25519"
	ed25519vm "github.com/ucan-wg/go-did-it/verifiers/_methods/ed25519"
	_ "github.com/ucan-wg/go-did-it/verifiers/did-key"
)

func TestJsonRoundTrip2020(t *testing.T) {
	data := `{
		"id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		"type": "Ed25519VerificationKey2020",
		"controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		"publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	  }`

	var vk ed25519vm.VerificationKey2020
	err := json.Unmarshal([]byte(data), &vk)
	require.NoError(t, err)

	bytes, err := json.Marshal(vk)
	require.NoError(t, err)
	require.JSONEq(t, data, string(bytes))
}

func TestSignature2020(t *testing.T) {
	// test vector from https://datatracker.ietf.org/doc/html/rfc8032#section-7.1

	pkHex := "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
	pkBytes := must(hex.DecodeString(pkHex))
	pk, err := ed25519.PublicKeyFromBytes(pkBytes)
	require.NoError(t, err)

	contDid := "did:key:" + pk.ToPublicKeyMultibase()
	controller := did.MustParse(contDid)
	vk := ed25519vm.NewVerificationKey2020("foo", pk, controller)

	for _, tc := range []struct {
		name      string
		data      []byte
		signature []byte
		valid     bool
	}{
		{
			name: "valid",
			data: must(hex.DecodeString("af82")),
			signature: must(hex.DecodeString(
				"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" +
					"18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
			)),
			valid: true,
		},
		{
			name: "data changed",
			data: must(hex.DecodeString("af8211")),
			signature: must(hex.DecodeString(
				"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" +
					"18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
			)),
			valid: false,
		},
		{
			name: "signature changed",
			data: must(hex.DecodeString("af82")),
			signature: must(hex.DecodeString(
				"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" +
					"18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a11",
			)),
			valid: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := vk.Verify(tc.data, tc.signature)
			require.NoError(t, err)
			require.Equal(t, tc.valid, valid)
		})
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
