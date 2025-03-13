package ed25519_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	_ "github.com/INFURA/go-did/did-key"
	"github.com/INFURA/go-did/verifications/ed25519"
)

func TestJson(t *testing.T) {
	data := `{
		"id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		"type": "Ed25519VerificationKey2020",
		"controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		"publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	  }`

	var vm ed25519.VerificationKey2020
	err := json.Unmarshal([]byte(data), &vm)
	require.NoError(t, err)

	bytes, err := json.Marshal(vm)
	require.NoError(t, err)
	require.JSONEq(t, data, string(bytes))
}
