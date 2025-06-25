package document

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	_ "github.com/INFURA/go-did/methods/did-key"
	"github.com/INFURA/go-did/verifications/ed25519"
	"github.com/INFURA/go-did/verifications/jsonwebkey"
	"github.com/INFURA/go-did/verifications/x25519"
)

func TestRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name      string
		strDoc    string
		assertion func(t *testing.T, doc *Document)
	}{
		{
			name:   "ed25519",
			strDoc: ed25519Doc,
			assertion: func(t *testing.T, doc *Document) {
				require.Equal(t, "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", doc.ID())
				require.Equal(t, ed25519vm.Type, doc.Authentication()[0].Type())
				require.Equal(t, ed25519vm.Type, doc.Assertion()[0].Type())
				require.Equal(t, x25519vm.Type, doc.KeyAgreement()[0].Type())
				require.Equal(t, ed25519vm.Type, doc.CapabilityInvocation()[0].Type())
				require.Equal(t, ed25519vm.Type, doc.CapabilityDelegation()[0].Type())
			},
		},
		{
			name:   "jsonWebKey",
			strDoc: jsonWebKeyDoc,
			assertion: func(t *testing.T, doc *Document) {
				require.Equal(t, "did:example:123", doc.ID())
				require.Len(t, doc.VerificationMethods(), 6)
				require.Equal(t, jsonwebkey.Type, doc.verificationMethods["did:example:123#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A"].Type())
				require.Equal(t, jsonwebkey.Type, doc.verificationMethods["did:example:123#4SZ-StXrp5Yd4_4rxHVTCYTHyt4zyPfN1fIuYsm6k3A"].Type())
				require.Equal(t, jsonwebkey.Type, doc.verificationMethods["did:example:123#n4cQ-I_WkHMcwXBJa7IHkYu8CMfdNcZKnKsOrnHLpFs"].Type())
				require.Equal(t, jsonwebkey.Type, doc.verificationMethods["did:example:123#_TKzHv2jFIyvdTGF1Dsgwngfdg3SH6TpDv0Ta1aOEkw"].Type())
				require.Equal(t, jsonwebkey.Type, doc.verificationMethods["did:example:123#8wgRfY3sWmzoeAL-78-oALNvNj67ZlQxd1ss_NX1hZY"].Type())
				require.Equal(t, jsonwebkey.Type, doc.verificationMethods["did:example:123#NjQ6Y_ZMj6IUK_XkgCDwtKHlNTUTVjEYOWZtxhp1n-E"].Type())
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := FromJsonBytes([]byte(tc.strDoc))
			require.NoError(t, err)

			tc.assertion(t, doc)

			roundtrip, err := json.Marshal(doc)
			require.NoError(t, err)
			require.JSONEq(t, tc.strDoc, string(roundtrip))
		})
	}
}

const ed25519Doc = `
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://w3id.org/security/suites/x25519-2020/v1"
  ],
  "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "verificationMethod": [{
    "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  }],
  "authentication": [
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  ],
  "assertionMethod": [
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  ],
  "capabilityDelegation": [
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  ],
  "capabilityInvocation": [
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  ],
  "keyAgreement": [{
    "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p",
    "type": "X25519KeyAgreementKey2020",
    "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "publicKeyMultibase": "z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p"
  }]
}
`

const jsonWebKeyDoc = `
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
  "id": "did:example:123",
  "verificationMethod": [
    {
      "id": "did:example:123#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A",
      "type": "JsonWebKey2020",
      "controller": "did:example:123",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ"
      }
    },
    {
      "id": "did:example:123#4SZ-StXrp5Yd4_4rxHVTCYTHyt4zyPfN1fIuYsm6k3A",
      "type": "JsonWebKey2020",
      "controller": "did:example:123",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "secp256k1",
        "x": "Z4Y3NNOxv0J6tCgqOBFnHnaZhJF6LdulT7z8A-2D5_8",
        "y": "i5a2NtJoUKXkLm6q8nOEu9WOkso1Ag6FTUT6k_LMnGk"
      }
    },
    {
      "id": "did:example:123#n4cQ-I_WkHMcwXBJa7IHkYu8CMfdNcZKnKsOrnHLpFs",
      "type": "JsonWebKey2020",
      "controller": "did:example:123",
      "publicKeyJwk": {
        "kty": "RSA",
        "e": "AQAB",
        "n": "omwsC1AqEk6whvxyOltCFWheSQvv1MExu5RLCMT4jVk9khJKv8JeMXWe3bWHatjPskdf2dlaGkW5QjtOnUKL742mvr4tCldKS3ULIaT1hJInMHHxj2gcubO6eEegACQ4QSu9LO0H-LM_L3DsRABB7Qja8HecpyuspW1Tu_DbqxcSnwendamwL52V17eKhlO4uXwv2HFlxufFHM0KmCJujIKyAxjD_m3q__IiHUVHD1tDIEvLPhG9Azsn3j95d-saIgZzPLhQFiKluGvsjrSkYU5pXVWIsV-B2jtLeeLC14XcYxWDUJ0qVopxkBvdlERcNtgF4dvW4X00EHj4vCljFw"
      }
    },
    {
      "id": "did:example:123#_TKzHv2jFIyvdTGF1Dsgwngfdg3SH6TpDv0Ta1aOEkw",
      "type": "JsonWebKey2020",
      "controller": "did:example:123",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "38M1FDts7Oea7urmseiugGW7tWc3mLpJh6rKe7xINZ8",
        "y": "nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4"
      }
    },
    {
      "id": "did:example:123#8wgRfY3sWmzoeAL-78-oALNvNj67ZlQxd1ss_NX1hZY",
      "type": "JsonWebKey2020",
      "controller": "did:example:123",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-384",
        "x": "GnLl6mDti7a2VUIZP5w6pcRX8q5nvEIgB3Q_5RI2p9F_QVsaAlDN7IG68Jn0dS_F",
        "y": "jq4QoAHKiIzezDp88s_cxSPXtuXYFliuCGndgU4Qp8l91xzD1spCmFIzQgVjqvcP"
      }
    },
    {
      "id": "did:example:123#NjQ6Y_ZMj6IUK_XkgCDwtKHlNTUTVjEYOWZtxhp1n-E",
      "type": "JsonWebKey2020",
      "controller": "did:example:123",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-521",
        "x": "AVlZG23LyXYwlbjbGPMxZbHmJpDSu-IvpuKigEN2pzgWtSo--Rwd-n78nrWnZzeDc187Ln3qHlw5LRGrX4qgLQ-y",
        "y": "ANIbFeRdPHf1WYMCUjcPz-ZhecZFybOqLIJjVOlLETH7uPlyG0gEoMWnIZXhQVypPy_HtUiUzdnSEPAylYhHBTX2"
      }
    }
  ],
  "authentication": [
    "did:example:123#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A",
    "did:example:123#4SZ-StXrp5Yd4_4rxHVTCYTHyt4zyPfN1fIuYsm6k3A",
    "did:example:123#n4cQ-I_WkHMcwXBJa7IHkYu8CMfdNcZKnKsOrnHLpFs",
    "did:example:123#_TKzHv2jFIyvdTGF1Dsgwngfdg3SH6TpDv0Ta1aOEkw",
    "did:example:123#8wgRfY3sWmzoeAL-78-oALNvNj67ZlQxd1ss_NX1hZY",
    "did:example:123#NjQ6Y_ZMj6IUK_XkgCDwtKHlNTUTVjEYOWZtxhp1n-E"
  ],
  "assertionMethod": [
    "did:example:123#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A",
    "did:example:123#4SZ-StXrp5Yd4_4rxHVTCYTHyt4zyPfN1fIuYsm6k3A",
    "did:example:123#n4cQ-I_WkHMcwXBJa7IHkYu8CMfdNcZKnKsOrnHLpFs",
    "did:example:123#_TKzHv2jFIyvdTGF1Dsgwngfdg3SH6TpDv0Ta1aOEkw",
    "did:example:123#8wgRfY3sWmzoeAL-78-oALNvNj67ZlQxd1ss_NX1hZY",
    "did:example:123#NjQ6Y_ZMj6IUK_XkgCDwtKHlNTUTVjEYOWZtxhp1n-E"
  ],
  "capabilityDelegation": [
    "did:example:123#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A",
    "did:example:123#4SZ-StXrp5Yd4_4rxHVTCYTHyt4zyPfN1fIuYsm6k3A",
    "did:example:123#n4cQ-I_WkHMcwXBJa7IHkYu8CMfdNcZKnKsOrnHLpFs",
    "did:example:123#_TKzHv2jFIyvdTGF1Dsgwngfdg3SH6TpDv0Ta1aOEkw",
    "did:example:123#8wgRfY3sWmzoeAL-78-oALNvNj67ZlQxd1ss_NX1hZY",
    "did:example:123#NjQ6Y_ZMj6IUK_XkgCDwtKHlNTUTVjEYOWZtxhp1n-E"
  ],
  "capabilityInvocation": [
    "did:example:123#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A",
    "did:example:123#4SZ-StXrp5Yd4_4rxHVTCYTHyt4zyPfN1fIuYsm6k3A",
    "did:example:123#n4cQ-I_WkHMcwXBJa7IHkYu8CMfdNcZKnKsOrnHLpFs",
    "did:example:123#_TKzHv2jFIyvdTGF1Dsgwngfdg3SH6TpDv0Ta1aOEkw",
    "did:example:123#8wgRfY3sWmzoeAL-78-oALNvNj67ZlQxd1ss_NX1hZY",
    "did:example:123#NjQ6Y_ZMj6IUK_XkgCDwtKHlNTUTVjEYOWZtxhp1n-E"
  ]
}
`
