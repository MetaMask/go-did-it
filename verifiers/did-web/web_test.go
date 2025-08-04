package did_web

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MetaMask/go-did-it"
)

func TestDecode(t *testing.T) {
	testcases := []struct {
		did   string
		valid bool
	}{
		{"did:web:w3c-ccg.github.io", true},
		{"did:web:w3c-ccg.github.io:user:alice", true},
		{"did:web:example.com%3A3000", true},
	}

	for _, tc := range testcases {
		t.Run(tc.did, func(t *testing.T) {
			_, err := Decode(tc.did)
			if tc.valid && err != nil {
				t.Errorf("Decode(%q) = %v, want nil", tc.did, err)
			} else if !tc.valid && err == nil {
				t.Errorf("Decode(%q) = nil, want error", tc.did)
			}
		})
	}
}

func TestIsValidHost(t *testing.T) {
	testcases := []struct {
		host  string
		valid bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"example.com:8080", true},
		{"w3c-ccg.github.io", true},
		{"192.168.1.1", false},
		{"invalid..com", false},
		{".example.com", false},
		{"example.com.", true},
		{"", false},
		{"just_invalid", false},
		{"-example.com", false},
		{"example.com-", false},
	}
	for _, tc := range testcases {
		t.Run(tc.host, func(t *testing.T) {
			if isValidHost(tc.host) != tc.valid {
				t.Errorf("isValidHost(%q) = %v, want %v", tc.host, isValidHost(tc.host), tc.valid)
			}
		})
	}
}

func TestResolution(t *testing.T) {
	client := &MockHTTPClient{
		url: "https://example.com/.well-known/did.json",
		resp: `{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://w3id.org/security/suites/x25519-2020/v1"
  ],
  "id": "did:web:example.com",
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
}`,
	}

	d, err := Decode("did:web:example.com")
	require.NoError(t, err)

	doc, err := d.Document(did.WithHttpClient(client))
	require.NoError(t, err)

	require.Equal(t, "did:web:example.com", doc.ID())
	require.Len(t, doc.VerificationMethods(), 1)
	require.Len(t, doc.Authentication(), 1)
	require.Len(t, doc.Assertion(), 1)
	require.Len(t, doc.KeyAgreement(), 1)
}

type MockHTTPClient struct {
	url  string
	resp string
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if req.URL.String() != m.url {
		return nil, fmt.Errorf("unexpected url: %s", req.URL.String())
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(m.resp)),
	}, nil
}
