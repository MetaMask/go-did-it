package didplc

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MetaMask/go-did-it"
)

func TestDocument(t *testing.T) {
	// current resolved /data for did:plc:ewvi7nxzyoun6zhxrhs64oiz
	resolvedData := `{"did":"did:plc:ewvi7nxzyoun6zhxrhs64oiz","verificationMethods":{"atproto":"did:key:zQ3shunBKsXixLxKtC5qeSG9E4J5RkGN57im31pcTzbNQnm5w"},"rotationKeys":["did:key:zQ3shhCGUqDKjStzuDxPkTxN6ujddP4RkEKJJouJGRRkaLGbg","did:key:zQ3shpKnbdPx3g3CmPf5cRVTPe1HtSwVn5ish3wSnDPQCbLJK"],"alsoKnownAs":["at://atproto.com"],"services":{"atproto_pds":{"type":"AtprotoPersonalDataServer","endpoint":"https://enoki.us-east.host.bsky.network"}}}`

	// as resolved by https://plc.directory/did:plc:ewvi7nxzyoun6zhxrhs64oiz
	// the original json had an additional
	// "https://w3id.org/security/suites/secp256k1-2019/v1" context that
	// I removed as it's just wrong
	expectedJson := `
{
  "@context":[
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/multikey/v1"
  ],
  "id":"did:plc:ewvi7nxzyoun6zhxrhs64oiz",
  "alsoKnownAs":[
    "at://atproto.com"
  ],
  "verificationMethod":[
    {
      "id":"did:plc:ewvi7nxzyoun6zhxrhs64oiz#atproto",
      "type":"Multikey",
      "controller":"did:plc:ewvi7nxzyoun6zhxrhs64oiz",
      "publicKeyMultibase":"zQ3shunBKsXixLxKtC5qeSG9E4J5RkGN57im31pcTzbNQnm5w"
    }
  ],
  "service":[
    {
      "id":"#atproto_pds",
      "type":"AtprotoPersonalDataServer",
      "serviceEndpoint":"https://enoki.us-east.host.bsky.network"
    }
  ]
}
`

	mockClient := &MockHTTPClient{resp: resolvedData}

	d, err := did.Parse("did:plc:ewvi7nxzyoun6zhxrhs64oiz")
	require.NoError(t, err)

	doc, err := d.Document(did.WithHttpClient(mockClient))
	require.NoError(t, err)

	docBytes, err := json.Marshal(doc)
	require.NoError(t, err)

	require.JSONEq(t, expectedJson, string(docBytes))
}

type MockHTTPClient struct {
	resp string
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(m.resp)),
	}, nil
}
