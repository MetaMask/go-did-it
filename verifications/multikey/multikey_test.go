package multikey_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	_ "github.com/ucan-wg/go-did-it/methods/did-key"
	"github.com/ucan-wg/go-did-it/verifications/multikey"
)

func TestJsonRoundTrip(t *testing.T) {
	data := `{
		"id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		"type": "Multikey",
		"controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		"publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	}`

	var mk multikey.MultiKey
	err := json.Unmarshal([]byte(data), &mk)
	require.NoError(t, err)

	bytes, err := json.Marshal(mk)
	require.NoError(t, err)
	require.JSONEq(t, data, string(bytes))
}
