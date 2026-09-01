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

// WithFullChainVerification fetches the DID's complete history (GET /:did/log/audit) and
// replays it before signing anything, instead of trusting the registry's report of the
// current state.
//
// The replay makes the state self-authenticating: the DID must be the hash of the genesis
// operation, every operation must point at an operation standing at the time and be
// signed by one of its rotation keys, and every recovery must have been signed by a
// higher-authority key inside the recovery window, with the nullified flags matching. It
// costs one response proportional to the length of the history, per operation signed.
//
// Without it — the default — [Controller.Head] reads only the latest operation
// (GET /:did/log/last): one small response whatever the length of the history, but
// nothing ties the operation the registry returns to the DID, so a fabricated or stale
// state is not detected. In both modes an operation is only signed if the signer holds
// one of the rotation keys of the state being built on, and [Controller.Audit] always
// validates in full.
func WithFullChainVerification() Option {
	return func(r *Registry) { r.fullVerification = true }
}

// WithRotationKeyPolicy sets the key algorithms accepted for rotation keys. Defaults to
// secp256k1 and P-256, the only two the specification allows.
//
// The policy governs both directions: which keys may be used to create an operation, and
// which rotation keys of a fetched operation are decoded to check its signature. So
// narrowing it (to P-256 only, say) is a way to refuse weaker keys in a history, while
// widening it accepts operations that the canonical registry would reject.
func WithRotationKeyPolicy(kp *crypto.KeyPolicy) Option {
	return func(r *Registry) { r.codec.rotationPolicy = kp }
}

// WithVerificationMethodKeyPolicy sets the key algorithms accepted for verification
// methods. Defaults to secp256k1, P-256 and Ed25519: the specification allows any
// did:key algorithm, but these are the ones that occur in practice.
//
// Widening it is safe, since verification-method keys carry no authority over the DID; it
// is only needed to read a DID that publishes an unusual key type.
func WithVerificationMethodKeyPolicy(kp *crypto.KeyPolicy) Option {
	return func(r *Registry) { r.codec.vmPolicy = kp }
}
