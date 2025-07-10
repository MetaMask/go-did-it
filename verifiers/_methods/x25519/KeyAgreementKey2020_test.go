package x25519vm_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ucan-wg/go-did-it/verifiers/_methods/x25519"
)

func TestJsonRoundTrip2020(t *testing.T) {
	data := `{
      "id": "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#z6LShs9GGnqk85isEBzzshkuVWrVKsRp24GnDuHk8QWkARMW",
      "type": "X25519KeyAgreementKey2020",
      "controller": "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
      "publicKeyMultibase": "z6LShs9GGnqk85isEBzzshkuVWrVKsRp24GnDuHk8QWkARMW"
    }`

	var vm x25519vm.KeyAgreementKey2020
	err := json.Unmarshal([]byte(data), &vm)
	require.NoError(t, err)

	bytes, err := json.Marshal(vm)
	require.NoError(t, err)
	require.JSONEq(t, data, string(bytes))
}
