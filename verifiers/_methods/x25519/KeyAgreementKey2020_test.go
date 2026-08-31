package x25519vm_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/x25519"
	methods "github.com/MetaMask/go-did-it/verifiers/_methods"
	x25519vm "github.com/MetaMask/go-did-it/verifiers/_methods/x25519"
)

const key2020Json = `{
	"id": "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#z6LShs9GGnqk85isEBzzshkuVWrVKsRp24GnDuHk8QWkARMW",
	"type": "X25519KeyAgreementKey2020",
	"controller": "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
	"publicKeyMultibase": "z6LShs9GGnqk85isEBzzshkuVWrVKsRp24GnDuHk8QWkARMW"
}`

func TestJsonRoundTrip2020(t *testing.T) {
	vm, err := x25519vm.NewKeyAgreementKey2020FromJSON([]byte(key2020Json), crypto.NewKeyPolicy(x25519.KeyType()))
	require.NoError(t, err)

	bytes, err := json.Marshal(vm)
	require.NoError(t, err)
	require.JSONEq(t, key2020Json, string(bytes))
}

// json.Unmarshal must fail rather than quietly produce an empty verification method.
func TestUnmarshalJSONRefused2020(t *testing.T) {
	var vm x25519vm.KeyAgreementKey2020
	err := json.Unmarshal([]byte(key2020Json), &vm)
	require.ErrorIs(t, err, methods.ErrDirectUnmarshal)
}

func TestKeyPolicyEnforcement2020(t *testing.T) {
	_, err := x25519vm.NewKeyAgreementKey2020FromJSON([]byte(key2020Json), crypto.NewKeyPolicy())
	require.ErrorIs(t, err, crypto.ErrKeyNotAccepted)
}
