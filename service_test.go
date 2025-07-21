package did

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServicesJsonRountrip(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "LinkedDomains",
			input: `[
    {
      "id":"did:example:123#foo",
      "type": "LinkedDomains",
      "serviceEndpoint": {
        "origins": ["https://foo.example.com", "https://identity.foundation"]
      }
    },
    {
      "id":"did:example:123#bar",
      "type": "LinkedDomains",
      "serviceEndpoint": "https://bar.example.com"
    }
  ]`,
		},
		{
			name: "LinkedVerifiablePresentation",
			input: `[
    {
      "id": "did:example:123#foo",
      "type": "LinkedVerifiablePresentation",
      "serviceEndpoint": "https://bar.example.com/verifiable-presentation.jsonld"
    },
    {
      "id": "did:example:123#baz",
      "type": "LinkedVerifiablePresentation",
      "serviceEndpoint": "ipfs://bafybeihkoviema7g3gxyt6la7vd5ho32ictqbilu3wnlo3rs7ewhnp7lly/verifiable-presentation.jwt"
    }
  ]`,
		},
		{
			name: "WotThing",
			input: `[{
      "id": "did:example:wotdiscoveryexample#td",
      "type": "WotThing",
      "serviceEndpoint":
          "https://wot.example.com/.well-known/wot"
  }]`,
		},
		{
			name: "multi types",
			input: `[
    {
      "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#node",
      "type": [
        "DIDCommMessaging",
        "CredentialRepositoryService",
        "RevocationList2020Status",
        "TrustRegistryService"
      ],
      "serviceEndpoint": "https://node.blockchain-network.com/api/v1"
    }
  ]`,
		},
		{
			name: "multi types, map values",
			input: `[
    {
      "id": "did:web:wallet.example.com#wallet-service",
      "type": [
        "VerifiableCredentialService",
        "OpenIdConnectVersion1.0Service",
        "DIDCommMessaging",
        "CredentialRepositoryService"
      ],
      "serviceEndpoint": {
        "credentialIssue": "https://wallet.example.com/credentials/issue",
        "credentialVerify": "https://wallet.example.com/credentials/verify",
        "credentialStore": "https://wallet.example.com/vault",
        "oidcAuth": "https://wallet.example.com/auth",
        "oidcToken": "https://wallet.example.com/token",
        "didcommInbox": "https://wallet.example.com/didcomm/inbox",
        "didcommOutbox": "https://wallet.example.com/didcomm/outbox"
      }
    }
  ]`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var services []Service
			err := json.Unmarshal([]byte(tc.input), &services)
			require.NoError(t, err)

			rt, err := json.Marshal(services)
			require.NoError(t, err)
			require.JSONEq(t, tc.input, string(rt))
		})
	}
}
