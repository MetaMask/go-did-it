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

const key2019Json = `{
	"id": "#z6LSkkqoZRC34AEpbkhZCqLDcHQVAxuLpQ7kC8XCXMVUfvjE",
	"type": "X25519KeyAgreementKey2019",
	"controller": "did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf",
	"publicKeyBase58": "A5fe37PAxhX5WNKngBpGHhC1KpNE7nwbK9oX2tqwxYxU"
}`

func TestJsonRoundTrip2019(t *testing.T) {
	vm, err := x25519vm.NewKeyAgreementKey2019FromJSON([]byte(key2019Json), crypto.NewKeyPolicy(x25519.KeyType()))
	require.NoError(t, err)

	bytes, err := json.Marshal(vm)
	require.NoError(t, err)
	require.JSONEq(t, key2019Json, string(bytes))
}

// json.Unmarshal must fail rather than quietly produce an empty verification method.
func TestUnmarshalJSONRefused2019(t *testing.T) {
	var vm x25519vm.KeyAgreementKey2019
	err := json.Unmarshal([]byte(key2019Json), &vm)
	require.ErrorIs(t, err, methods.ErrDirectUnmarshal)
}

func TestKeyPolicyEnforcement2019(t *testing.T) {
	_, err := x25519vm.NewKeyAgreementKey2019FromJSON([]byte(key2019Json), crypto.NewKeyPolicy())
	require.ErrorIs(t, err, crypto.ErrKeyNotAccepted)
}
