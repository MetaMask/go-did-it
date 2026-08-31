package p256vm_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/p256"
	methods "github.com/MetaMask/go-did-it/verifiers/methods"
	p256vm "github.com/MetaMask/go-did-it/verifiers/methods/p256"
)

const key2021Json = `{
	"id": "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb#zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb",
	"type": "P256Key2021",
	"controller": "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb",
	"publicKeyBase58": "ekVhkcBFq3w7jULLkBVye6PwaTuMbhJYuzwFnNcgQAPV"
}`

func TestJsonRoundTrip(t *testing.T) {
	mk, err := p256vm.NewKey2021FromJSON([]byte(key2021Json), crypto.NewKeyPolicy(p256.KeyType()))
	require.NoError(t, err)

	bytes, err := json.Marshal(mk)
	require.NoError(t, err)
	require.JSONEq(t, key2021Json, string(bytes))
}

// json.Unmarshal must fail rather than quietly produce an empty verification method.
func TestUnmarshalJSONRefused(t *testing.T) {
	var mk p256vm.Key2021
	err := json.Unmarshal([]byte(key2021Json), &mk)
	require.ErrorIs(t, err, methods.ErrDirectUnmarshal)
}

func TestKeyPolicyEnforcement(t *testing.T) {
	_, err := p256vm.NewKey2021FromJSON([]byte(key2021Json), crypto.NewKeyPolicy())
	require.ErrorIs(t, err, crypto.ErrKeyNotAccepted)
}
