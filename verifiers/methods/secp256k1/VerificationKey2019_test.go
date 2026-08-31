package secp256k1vm_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MetaMask/go-did-it/crypto"
	secp256k1crypto "github.com/MetaMask/go-did-it/crypto/secp256k1"
	methods "github.com/MetaMask/go-did-it/verifiers/methods"
	secp256k1vm "github.com/MetaMask/go-did-it/verifiers/methods/secp256k1"
)

const key2019Json = `{
	"id": "did:key:zQ3shadCps5JLAHcZiuX5YUtWHHL8ysBJqFLWvjZDKAWUBGzy#zQ3shadCps5JLAHcZiuX5YUtWHHL8ysBJqFLWvjZDKAWUBGzy",
	"type": "EcdsaSecp256k1VerificationKey2019",
	"controller": "did:key:zQ3shadCps5JLAHcZiuX5YUtWHHL8ysBJqFLWvjZDKAWUBGzy",
	"publicKeyBase58": "pg3p1vprqePgUoqfAQ1TTgxhL6zLYhHyzooR1pqLxo9F"
}`

func TestJsonRoundTrip(t *testing.T) {
	mk, err := secp256k1vm.NewVerificationKey2019FromJSON([]byte(key2019Json), crypto.NewKeyPolicy(secp256k1crypto.KeyType()))
	require.NoError(t, err)

	bytes, err := json.Marshal(mk)
	require.NoError(t, err)
	require.JSONEq(t, key2019Json, string(bytes))
}

// json.Unmarshal must fail rather than quietly produce an empty verification method.
func TestUnmarshalJSONRefused2019(t *testing.T) {
	var mk secp256k1vm.VerificationKey2019
	err := json.Unmarshal([]byte(key2019Json), &mk)
	require.ErrorIs(t, err, methods.ErrDirectUnmarshal)
}

func TestKeyPolicyEnforcement2019(t *testing.T) {
	_, err := secp256k1vm.NewVerificationKey2019FromJSON([]byte(key2019Json), crypto.NewKeyPolicy())
	require.ErrorIs(t, err, crypto.ErrKeyNotAccepted)
}
