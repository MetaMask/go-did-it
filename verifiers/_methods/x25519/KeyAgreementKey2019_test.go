package x25519vm_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ucan-wg/go-did-it/verifiers/_methods/x25519"
)

func TestJsonRoundTrip2019(t *testing.T) {
	data := `{
      "id": "#z6LSkkqoZRC34AEpbkhZCqLDcHQVAxuLpQ7kC8XCXMVUfvjE",
      "type": "X25519KeyAgreementKey2019",
      "controller": "did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf",
      "publicKeyBase58": "A5fe37PAxhX5WNKngBpGHhC1KpNE7nwbK9oX2tqwxYxU"
    }`

	var vm x25519vm.KeyAgreementKey2019
	err := json.Unmarshal([]byte(data), &vm)
	require.NoError(t, err)

	bytes, err := json.Marshal(vm)
	require.NoError(t, err)
	require.JSONEq(t, data, string(bytes))
}
