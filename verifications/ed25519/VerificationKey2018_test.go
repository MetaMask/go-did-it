package ed25519vm_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	ed25519vm "github.com/INFURA/go-did/verifications/ed25519"
)

func TestJsonRoundTrip2018(t *testing.T) {
	data := `{
          "id": "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG#z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG",
          "type": "Ed25519VerificationKey2018",
          "controller": "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG",
          "publicKeyBase58": "6ASf5EcmmEHTgDJ4X4ZT5vT6iHVJBXPg5AN5YoTCpGWt"
        }`

	var vk ed25519vm.VerificationKey2018
	err := json.Unmarshal([]byte(data), &vk)
	require.NoError(t, err)

	bytes, err := json.Marshal(vk)
	require.NoError(t, err)
	require.JSONEq(t, data, string(bytes))
}
