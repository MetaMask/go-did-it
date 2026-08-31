package multikey_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/ed25519"
	methods "github.com/MetaMask/go-did-it/verifiers/_methods"
	"github.com/MetaMask/go-did-it/verifiers/_methods/multikey"
	_ "github.com/MetaMask/go-did-it/verifiers/did-key"
)

const multikeyJson = `{
	"id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
	"type": "Multikey",
	"controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
	"publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
}`

func TestJsonRoundTrip(t *testing.T) {
	mk, err := multikey.NewMultiKeyFromJSON([]byte(multikeyJson), crypto.NewKeyPolicy(ed25519.KeyType()))
	require.NoError(t, err)

	bytes, err := json.Marshal(mk)
	require.NoError(t, err)
	require.JSONEq(t, multikeyJson, string(bytes))
}

// json.Unmarshal must fail rather than quietly produce an empty verification method.
func TestUnmarshalJSONRefused(t *testing.T) {
	var mk multikey.MultiKey
	err := json.Unmarshal([]byte(multikeyJson), &mk)
	require.ErrorIs(t, err, methods.ErrDirectUnmarshal)
}

func TestKeyPolicyEnforcement(t *testing.T) {
	_, err := multikey.NewMultiKeyFromJSON([]byte(multikeyJson), crypto.NewKeyPolicy())
	require.ErrorIs(t, err, crypto.ErrKeyNotAccepted)
}
