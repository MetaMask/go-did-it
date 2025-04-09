package ed25519_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	_ "github.com/INFURA/go-did/methods/did-key"
	"github.com/INFURA/go-did/verifications/ed25519"
)

func TestJsonRoundTrip(t *testing.T) {
	data := `{
		"id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		"type": "Ed25519VerificationKey2020",
		"controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		"publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	  }`

	var vm ed25519.VerificationKey2020
	err := json.Unmarshal([]byte(data), &vm)
	require.NoError(t, err)

	bytes, err := json.Marshal(vm)
	require.NoError(t, err)
	require.JSONEq(t, data, string(bytes))
}

// func TestSignature(t *testing.T) {
// 	d, err := didkey.Decode("did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2")
// 	require.NoError(t, err)
// 	doc, err := d.Document()
// 	require.NoError(t, err)
// 	method := doc.Authentication()[0]
// 	require.IsType(t, &ed25519.VerificationKey2020{}, method)
//
// 	require.True(t, method.Verify(
// 		[]byte("node key test"),
// 		[]byte("Tuhz8eG2jqYG4jUbxt14iMd3r2v2eNLftPTfrZfaaFYn5ta7wP3oYfC1rnDVJsLvHAK7j5CmVoXtGoYGL7Lnb5e"),
// 	))
//
// 	// ed25519.NewVerificationKey2020(did, )
// }
