package did_plc

import (
	"net/http"

	"github.com/MetaMask/go-did-it/crypto"
)

// Option configures a Registry.
type Option func(*Registry)

// WithURL sets the PLC registry base URL. DefaultRegistry: https://plc.directory.
func WithURL(url string) Option {
	return func(r *Registry) { r.url = url }
}

// WithHTTPClient sets the HTTP client used for registry requests.
func WithHTTPClient(client *http.Client) Option {
	return func(r *Registry) { r.httpClient = client }
}

// WithRotationKeySet sets the allowed rotation key algorithms.
// DefaultRegistry: secp256k1 and P-256.
func WithRotationKeySet(ks *crypto.KeySet) Option {
	return func(r *Registry) { r.rotationKeySet = ks }
}
