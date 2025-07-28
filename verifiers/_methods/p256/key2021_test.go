package p256vm_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MetaMask/go-did-it/verifiers/_methods/p256"
)

func TestJsonRoundTrip(t *testing.T) {
	data := `{
          "id": "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb#zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb",
          "type": "P256Key2021",
          "controller": "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb",
          "publicKeyBase58": "ekVhkcBFq3w7jULLkBVye6PwaTuMbhJYuzwFnNcgQAPV"
        }`

	var mk p256vm.Key2021
	err := json.Unmarshal([]byte(data), &mk)
	require.NoError(t, err)

	bytes, err := json.Marshal(mk)
	require.NoError(t, err)
	require.JSONEq(t, data, string(bytes))
}
