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
//	ctrl, err := reg.Create(ctx, signer, didplcctl.Op{
//	    RotationKeys: []crypto.PublicKey{myKey},
//	    AlsoKnownAs:  []string{"at://alice.example.com"},
//	})
//
//	ctrl, err := reg.Controller("did:plc:...")
//	err = ctrl.Update(ctx, signer, func(op didplcctl.Op) (didplcctl.Op, error) {
//	    op.AlsoKnownAs = append(op.AlsoKnownAs, "at://alice.new.example.com")
//	    return op, nil
//	})
//
// # Chain verification
//
// Every operation is built on the DID's current state, which has to be fetched from
// the registry first. [ChainVerification] selects how much the registry is trusted to
// report that state, and is set once per Registry with [WithChainVerification]; see
// [VerifyFullChain] (the default) and [VerifyHeadOnly].
//
// Regardless of the mode, an operation is only signed if the signer's public key is
// one of the rotation keys of the state being built on. That check is what stops a
// hostile registry from feeding a controller a state that lists the registry's own
// rotation keys, for the controller to sign into place.
//
// # Key types
//
// Rotation keys must be secp256k1 or P-256, as required by the specification; see
// [WithRotationKeyPolicy]. Verification-method keys may be any type supported by the
// did:key method, restricted by [WithVerificationMethodKeyPolicy].
//
// # Organization
//
// [Registry] is the only configured object: the endpoint, how much to verify, and the two
// key policies all live there, and anything parameterized by them is a method on it.
// Configuration reaches only as far as the wire form — a key policy is consulted where
// did:key strings are decoded and nowhere else — which leaves the protocol rules in
// chain.go as free functions taking nothing but the operations themselves.
package didplcctl
