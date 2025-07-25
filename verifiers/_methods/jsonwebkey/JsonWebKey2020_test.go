package jsonwebkey

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJsonRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		str  string
	}{
		{
			name: "did:example:123#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A",
			str: `{
					  "id": "did:example:123#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A",
					  "type": "JsonWebKey2020",
					  "controller": "did:example:123",
					  "publicKeyJwk": {
						"kty": "OKP",
						"crv": "Ed25519",
						"x": "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ"
				  }}`,
		},
		{
			name: "did:example:123#4SZ-StXrp5Yd4_4rxHVTCYTHyt4zyPfN1fIuYsm6k3A",
			str: `{
					"id": "did:example:123#4SZ-StXrp5Yd4_4rxHVTCYTHyt4zyPfN1fIuYsm6k3A",
					"type": "JsonWebKey2020",
					"controller": "did:example:123",
					"publicKeyJwk": {
						"kty": "EC",
						"crv": "secp256k1",
						"x": "Z4Y3NNOxv0J6tCgqOBFnHnaZhJF6LdulT7z8A-2D5_8",
						"y": "i5a2NtJoUKXkLm6q8nOEu9WOkso1Ag6FTUT6k_LMnGk"
					}}`,
		},
		{
			name: "did:example:123#n4cQ-I_WkHMcwXBJa7IHkYu8CMfdNcZKnKsOrnHLpFs",
			str: `{
					"id": "did:example:123#n4cQ-I_WkHMcwXBJa7IHkYu8CMfdNcZKnKsOrnHLpFs",
					"type": "JsonWebKey2020",
					"controller": "did:example:123",
					"publicKeyJwk": {
						"kty": "RSA",
						"e": "AQAB",
						"n": "omwsC1AqEk6whvxyOltCFWheSQvv1MExu5RLCMT4jVk9khJKv8JeMXWe3bWHatjPskdf2dlaGkW5QjtOnUKL742mvr4tCldKS3ULIaT1hJInMHHxj2gcubO6eEegACQ4QSu9LO0H-LM_L3DsRABB7Qja8HecpyuspW1Tu_DbqxcSnwendamwL52V17eKhlO4uXwv2HFlxufFHM0KmCJujIKyAxjD_m3q__IiHUVHD1tDIEvLPhG9Azsn3j95d-saIgZzPLhQFiKluGvsjrSkYU5pXVWIsV-B2jtLeeLC14XcYxWDUJ0qVopxkBvdlERcNtgF4dvW4X00EHj4vCljFw"
					}}`,
		},
		{
			name: "did:example:123#_TKzHv2jFIyvdTGF1Dsgwngfdg3SH6TpDv0Ta1aOEkw",
			str: `{
					"id": "did:example:123#_TKzHv2jFIyvdTGF1Dsgwngfdg3SH6TpDv0Ta1aOEkw",
					"type": "JsonWebKey2020",
					"controller": "did:example:123",
					"publicKeyJwk": {
						"kty": "EC",
						"crv": "P-256",
						"x": "38M1FDts7Oea7urmseiugGW7tWc3mLpJh6rKe7xINZ8",
						"y": "nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4"
					}}`,
		},
		{
			name: "did:example:123#8wgRfY3sWmzoeAL-78-oALNvNj67ZlQxd1ss_NX1hZY",
			str: `{
					"id": "did:example:123#8wgRfY3sWmzoeAL-78-oALNvNj67ZlQxd1ss_NX1hZY",
					"type": "JsonWebKey2020",
					"controller": "did:example:123",
					"publicKeyJwk": {
						"kty": "EC",
						"crv": "P-384",
						"x": "GnLl6mDti7a2VUIZP5w6pcRX8q5nvEIgB3Q_5RI2p9F_QVsaAlDN7IG68Jn0dS_F",
						"y": "jq4QoAHKiIzezDp88s_cxSPXtuXYFliuCGndgU4Qp8l91xzD1spCmFIzQgVjqvcP"
					}}`,
		},
		{
			name: "did:example:123#NjQ6Y_ZMj6IUK_XkgCDwtKHlNTUTVjEYOWZtxhp1n-E",
			str: `{
					"id": "did:example:123#NjQ6Y_ZMj6IUK_XkgCDwtKHlNTUTVjEYOWZtxhp1n-E",
					"type": "JsonWebKey2020",
					"controller": "did:example:123",
					"publicKeyJwk": {
						"kty": "EC",
						"crv": "P-521",
						"x": "AVlZG23LyXYwlbjbGPMxZbHmJpDSu-IvpuKigEN2pzgWtSo--Rwd-n78nrWnZzeDc187Ln3qHlw5LRGrX4qgLQ-y",
						"y": "ANIbFeRdPHf1WYMCUjcPz-ZhecZFybOqLIJjVOlLETH7uPlyG0gEoMWnIZXhQVypPy_HtUiUzdnSEPAylYhHBTX2"
					}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var jwk JsonWebKey2020
			err := json.Unmarshal([]byte(tc.str), &jwk)
			require.NoError(t, err)

			bytes, err := json.Marshal(jwk)
			require.NoError(t, err)
			require.JSONEq(t, tc.str, string(bytes))
		})
	}
}
