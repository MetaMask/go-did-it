package jwk

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPublicJwksRoundtrip(t *testing.T) {
	in := `{
		"keys": [
			{
				"kid": "key-1",
				"kty": "OKP",
				"crv": "Ed25519",
				"x": "_eT7oDCtAC98L31MMx9J0T-w7HR-zuvsY08f9MvKne8"
			},
			{
				"kid": "key-2",
				"kty": "EC",
				"crv": "P-256",
				"x": "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns",
				"y": "efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM"
			}
		]
	}`

	var jwks PublicJwks
	err := json.Unmarshal([]byte(in), &jwks)
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 2)
	require.Equal(t, "key-1", jwks.Keys[0].Kid)
	require.Equal(t, "key-2", jwks.Keys[1].Kid)

	out, err := json.Marshal(jwks)
	require.NoError(t, err)
	require.JSONEq(t, in, string(out))
}

func TestPrivateJwksRoundtrip(t *testing.T) {
	in := `{
		"keys": [
			{
				"kid": "key-1",
				"kty": "OKP",
				"crv": "Ed25519",
				"x": "_eT7oDCtAC98L31MMx9J0T-w7HR-zuvsY08f9MvKne8",
				"d": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAU"
			},
			{
				"kid": "key-2",
				"kty": "EC",
				"crv": "P-256",
				"x": "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns",
				"y": "efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM",
				"d": "gPh-VvVS8MbvKQ9LSVVmfnxnKjHn4Tqj0bmbpehRlpc"
			}
		]
	}`

	var jwks PrivateJwks
	err := json.Unmarshal([]byte(in), &jwks)
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 2)
	require.Equal(t, "key-1", jwks.Keys[0].Kid)
	require.Equal(t, "key-2", jwks.Keys[1].Kid)

	out, err := json.Marshal(jwks)
	require.NoError(t, err)
	require.JSONEq(t, in, string(out))
}
