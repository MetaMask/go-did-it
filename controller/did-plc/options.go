package didplcctl

import (
	"github.com/MetaMask/go-did-it"
	"github.com/MetaMask/go-did-it/crypto"
)

// Option configures a Registry.
type Option func(*Registry)

// WithURL sets the PLC registry base URL. Defaults to [DefaultRegistry].
func WithURL(url string) Option {
	return func(r *Registry) { r.url = url }
}

// WithHttpClient sets the HTTP client used for registry requests.
func WithHttpClient(client did.HttpClient) Option {
	return func(r *Registry) { r.httpClient = client }
}

// WithChainVerification sets how much of the operation log is fetched and verified
// before an operation is signed. Defaults to [VerifyFullChain].
func WithChainVerification(v ChainVerification) Option {
	return func(r *Registry) { r.verification = v }
}

// WithRotationKeyPolicy sets the key algorithms accepted for rotation keys. Defaults to
// secp256k1 and P-256, the only two the specification allows.
//
// The policy governs both directions: which keys may be used to create an operation, and
// which rotation keys of a fetched operation are decoded to check its signature. So
// narrowing it (to P-256 only, say) is a way to refuse weaker keys in a history, while
// widening it accepts operations that the canonical registry would reject.
func WithRotationKeyPolicy(kp *crypto.KeyPolicy) Option {
	return func(r *Registry) { r.rotationPolicy = kp }
}

// WithVerificationMethodKeyPolicy sets the key algorithms accepted for verification
// methods. Defaults to secp256k1, P-256 and Ed25519: the specification allows any
// did:key algorithm, but these are the ones that occur in practice.
//
// Widening it is safe, since verification-method keys carry no authority over the DID; it
// is only needed to read a DID that publishes an unusual key type.
func WithVerificationMethodKeyPolicy(kp *crypto.KeyPolicy) Option {
	return func(r *Registry) { r.vmPolicy = kp }
}
