package didkey

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/INFURA/go-did"
	"github.com/INFURA/go-did/methods/did-key/testvectors"
)

func TestDocument(t *testing.T) {
	d, err := did.Parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
	require.NoError(t, err)

	doc, err := d.Document(did.WithResolutionHintVerificationMethod("Ed25519VerificationKey2020"))
	require.NoError(t, err)

	bytes, err := json.MarshalIndent(doc, "", "  ")
	require.NoError(t, err)

	const expected = `{
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
}`

	requireDocEqual(t, expected, string(bytes))
}

func TestVectors(t *testing.T) {
	for _, filename := range testvectors.AllFiles() {
		t.Run(filename, func(t *testing.T) {
			vectors, err := testvectors.LoadTestVectors(filename)
			require.NoError(t, err)

			for _, vector := range vectors {
				t.Run(vector.DID, func(t *testing.T) {
					t.Log("hint is", vector.ResolutionHint)
					require.NotZero(t, vector.Document)
					require.NotZero(t, vector.Pub)
					require.NotZero(t, vector.Priv)

					d, err := did.Parse(vector.DID)
					require.NoError(t, err)

					var opts []did.ResolutionOption
					for _, hint := range vector.ResolutionHint {
						opts = append(opts, did.WithResolutionHintVerificationMethod(hint))
					}

					doc, err := d.Document(opts...)
					require.NoError(t, err)
					bytes, err := json.MarshalIndent(doc, "", "  ")
					require.NoError(t, err)
					requireDocEqual(t, vector.Document, string(bytes))
				})
			}
		})
	}
}

// Some variations in the DID document are legal, so we can't just require.JSONEq() to compare two of them.
// This function does its best to compare two documents, regardless of those variations.
func requireDocEqual(t *testing.T, expected, actual string) {
	propsExpected := map[string]json.RawMessage{}
	err := json.Unmarshal([]byte(expected), &propsExpected)
	require.NoError(t, err)

	propsActual := map[string]json.RawMessage{}
	err = json.Unmarshal([]byte(actual), &propsActual)
	require.NoError(t, err)

	require.Equal(t, len(propsExpected), len(propsActual))

	// if a VerificationMethod is defined inline in the properties below, we move it to vmExpected and replace it with the VM ID
	var vmExpected []json.RawMessage
	err = json.Unmarshal(propsExpected["verificationMethod"], &vmExpected)
	require.NoError(t, err)

	for _, s := range []string{"authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", "capabilityDelegation"} {
		var vms []json.RawMessage
		err = json.Unmarshal(propsExpected[s], &vms)
		require.NoError(t, err)
		for _, vmBytes := range vms {
			vm := map[string]json.RawMessage{}
			if err := json.Unmarshal(vmBytes, &vm); err == nil {
				vmExpected = append(vmExpected, vmBytes)
				propsExpected[s] = append([]byte("[ "), append(vm["id"], []byte(" ]")...)...)
			}
		}
	}

	// Same for actual
	var vmActual []json.RawMessage
	err = json.Unmarshal(propsActual["verificationMethod"], &vmActual)
	require.NoError(t, err)

	for _, s := range []string{"authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", "capabilityDelegation"} {
		var vms []json.RawMessage
		err = json.Unmarshal(propsActual[s], &vms)
		require.NoError(t, err)
		for _, vmBytes := range vms {
			vm := map[string]json.RawMessage{}
			if err := json.Unmarshal(vmBytes, &vm); err == nil {
				vmActual = append(vmActual, vmBytes)
				propsActual[s] = append([]byte("[ "), append(vm["id"], []byte(" ]")...)...)
			}
		}
	}

	for k, v := range propsExpected {
		switch k {
		case "verificationMethod":
			// Convert to interface{} slices to normalize JSON formatting
			expectedVMs := make([]interface{}, len(vmExpected))
			for i, vm := range vmExpected {
				var normalized interface{}
				err := json.Unmarshal(vm, &normalized)
				require.NoError(t, err)
				expectedVMs[i] = normalized
			}

			actualVMs := make([]interface{}, len(vmActual))
			for i, vm := range vmActual {
				var normalized interface{}
				err := json.Unmarshal(vm, &normalized)
				require.NoError(t, err)
				actualVMs[i] = normalized
			}

			require.ElementsMatch(t, expectedVMs, actualVMs, "--> on property \"%s\"", k)
		default:
			require.JSONEq(t, string(v), string(propsActual[k]), "--> on property \"%s\"", k)
		}
	}
}
