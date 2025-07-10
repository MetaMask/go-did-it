package secp256k1vm_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	secp256k1vm "github.com/ucan-wg/go-did-it/verifications/secp256k1"
)

func TestJsonRoundTrip(t *testing.T) {
	data := `{
          "id": "did:key:zQ3shadCps5JLAHcZiuX5YUtWHHL8ysBJqFLWvjZDKAWUBGzy#zQ3shadCps5JLAHcZiuX5YUtWHHL8ysBJqFLWvjZDKAWUBGzy",
          "type": "EcdsaSecp256k1VerificationKey2019",
          "controller": "did:key:zQ3shadCps5JLAHcZiuX5YUtWHHL8ysBJqFLWvjZDKAWUBGzy",
          "publicKeyBase58": "pg3p1vprqePgUoqfAQ1TTgxhL6zLYhHyzooR1pqLxo9F"
        }`

	var mk secp256k1vm.VerificationKey2019
	err := json.Unmarshal([]byte(data), &mk)
	require.NoError(t, err)

	bytes, err := json.Marshal(mk)
	require.NoError(t, err)
	require.JSONEq(t, data, string(bytes))
}
