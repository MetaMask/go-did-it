// Package didplcctl implements the controller side of the did:plc method: creating
// DIDs, updating them, recovering a forked history, deactivating them, and auditing
// their operation log.
//
// Resolving a did:plc DID to a document is the job of the sibling package
// github.com/MetaMask/go-did-it/verifiers/did-plc, which this package builds on.
//
// did:plc is a self-authenticating, recoverable DID method backed by a public
// append-only log, by default the one hosted at https://plc.directory.
// Specification: https://web.plc.directory/spec/v0.1/did-plc
//
// # Usage
//
// Configure a [Registry] with [NewRegistry] and call [Registry.Create] to register a
// new DID, which returns a [Controller]. To operate on an existing DID, obtain a
// controller with [Registry.Controller].
//
//	reg := didplcctl.NewRegistry()
//	ctrl, err := reg.Create(ctx, signer, didplcctl.State{
//	    RotationKeys: []crypto.PublicKey{myKey},
//	    AlsoKnownAs:  []string{"at://alice.example.com"},
//	})
//
//	ctrl, err := reg.Controller("did:plc:...")
//	err = ctrl.Update(ctx, signer, func(state didplcctl.State) (didplcctl.State, error) {
//	    state.AlsoKnownAs = append(state.AlsoKnownAs, "at://alice.new.example.com")
//	    return state, nil
//	})
//
// A [State] is not an operation: it is the document state an operation establishes, which
// is the only part a caller has to think about. The operation that gets from one state to
// the next — its prev, its signature, its encodings — is built by this package.
//
// # Chain verification
//
// Every operation is built on the DID's current state, which has to be fetched from the
// registry first. By default that state is whatever the registry reports (GET
// /:did/log/last): one small response, taken on trust. [WithFullChainVerification] reads
// the DID's whole history instead and replays it, which makes the state
// self-authenticating at the cost of a response proportional to the length of that
// history.
//
// Regardless of the mode, an operation is only signed if the signer's public key is
// one of the rotation keys of the state being built on. That check is what stops a
// hostile registry from feeding a controller a state that lists the registry's own
// rotation keys, for the controller to sign into place. It does not stop a hostile
// registry from reporting a stale or fabricated state, which is what the full replay is
// for.
//
// [Controller.Audit] always replays in full, whatever the setting.
//
// # Key types
//
// Rotation keys must be secp256k1 or P-256, as required by the specification; see
// [WithRotationKeyPolicy]. Verification-method keys may be any type supported by the
// did:key method, restricted by [WithVerificationMethodKeyPolicy].
//
// # Organization
//
// The package is four layers, innermost first. Every file belongs to exactly one of them,
// and a type and its methods stay in one file — with a single deliberate exception, the
// codec, which spans two:
//
//	spec.go        the constants the specification pins, and the rule deriving a DID from
//	               the hash of its genesis operation
//
//	               the nouns — each declares a type and only its own methods:
//	key.go           a rotation key, and did:key, the form every key is carried in
//	state.go         State: what a caller supplies, and the limits on it
//	operation.go     one operation: its encodings, and what it can check about itself
//	chain.go         a DID's whole history: AuditEntry, Head, and the replay rules
//
//	               the codec, which turns State into operations and back, and is the only
//	               thing that applies a key policy:
//	codec.go         the type, the parse dispatch, and the two formats written as well as
//	                 read (plc_operation, plc_tombstone)
//	legacy.go        the deprecated "create" genesis format, only ever read
//
//	registry.go    HTTP transport, and RegistryError
//	options.go     the Option constructors
//	controller.go  Controller: the public API
//	errors.go      the sentinel errors
//
// Configuration reaches only as far as the codec: a key policy is consulted where did:key
// strings are encoded and decoded, and nowhere else. That is what leaves the protocol
// rules in chain.go taking nothing but the operations themselves — by the time an
// operation reaches them, its keys are keys.
package didplcctl
