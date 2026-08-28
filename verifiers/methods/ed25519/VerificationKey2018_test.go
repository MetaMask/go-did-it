package ed25519vm_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/ed25519"
	methods "github.com/MetaMask/go-did-it/verifiers/methods"
	ed25519vm "github.com/MetaMask/go-did-it/verifiers/methods/ed25519"
)

const key2018Json = `{
	"id": "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG#z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG",
	"type": "Ed25519VerificationKey2018",
	"controller": "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG",
	"publicKeyBase58": "6ASf5EcmmEHTgDJ4X4ZT5vT6iHVJBXPg5AN5YoTCpGWt"
}`

func TestJsonRoundTrip2018(t *testing.T) {
	vk, err := ed25519vm.NewVerificationKey2018FromJSON([]byte(key2018Json), crypto.NewKeyPolicy(ed25519.KeyType()))
	require.NoError(t, err)

	bytes, err := json.Marshal(vk)
	require.NoError(t, err)
	require.JSONEq(t, key2018Json, string(bytes))
}

// json.Unmarshal must fail rather than quietly produce an empty verification method.
func TestUnmarshalJSONRefused2018(t *testing.T) {
	var vk ed25519vm.VerificationKey2018
	err := json.Unmarshal([]byte(key2018Json), &vk)
	require.ErrorIs(t, err, methods.ErrDirectUnmarshal)
}

func TestKeyPolicyEnforcement2018(t *testing.T) {
	_, err := ed25519vm.NewVerificationKey2018FromJSON([]byte(key2018Json), crypto.NewKeyPolicy())
	require.ErrorIs(t, err, crypto.ErrKeyNotAccepted)
}
