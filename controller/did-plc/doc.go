// Package didplcctl implements the controller side of the did:plc method: creating DIDs,
// updating them, recovering a forked history, deactivating them, and auditing their
// operation log.
//
// Resolving a did:plc DID to a document is the job of the sibling package
// github.com/MetaMask/go-did-it/verifiers/did-plc, which this package builds on.
//
// Specification: https://web.plc.directory/spec/v0.1/did-plc
//
// # Usage
//
// Configure a [Registry] with [NewRegistry] and call [Registry.Create] to register a new
// DID, which returns a [Controller]. To operate on an existing DID, obtain a controller
// with [Registry.Controller].
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
// A [State] is not an operation. It is the document state an operation establishes, and
// the only part a caller has to think about; the operation that gets from one state to the
// next — its prev, its signature, its encodings — is built here. The rest of this doc is
// what that sentence is hiding, because most of this package only makes sense once the
// method does.
//
// # The operation log
//
// A did:plc DID is not stored anywhere. It is the hash of the first operation that ever
// created it, and its current state is the result of replaying every operation since.
// A registry — by default https://plc.directory — keeps those operations and serves them
// to anyone, but holds no authority over them.
//
// Each operation names its predecessor in a "prev" field. The first names none, and the
// DID is derived from it:
//
//	did:plc:ewvi7nxzyoun6zhxrhs64oiz
//	        ▲
//	        └── first 24 chars of base32(sha-256(genesis operation))
//
//	op1 ──────────► op2 ──────────► op3
//	prev: null      prev: cid(op1)  prev: cid(op2)
//
// That derivation is what makes the method self-authenticating. Given a DID and a log,
// anyone can check the log belongs to that DID, without trusting whoever served it: hash
// the first operation and compare.
//
// The log is not a straight line. A recovery points prev at an operation further back,
// which discards everything after that point:
//
//	       ┌── op2 ──── op3     nullified by op4, and no longer part of the DID
//	op1 ───┤
//	       └── op4 ──── op5     the live path
//
// Nullified operations are not deleted — the registry keeps serving them, flagged — but
// nothing may ever build on one again. Exactly one root-to-leaf path is live at any
// moment, and that path alone determines the DID's state.
//
// # Rotation keys and authority
//
// Every operation carries a list of rotation keys, and that list is what authorizes the
// *next* operation. An operation's own rotation keys grant it nothing:
//
//	op3                                    op4
//	rotationKeys: [ A, B, C ]  ─────────►  must be signed by A, B or C
//	                ▲       ▲
//	                │       └── lowest authority
//	                └── highest authority
//
// Otherwise anyone could write an operation listing their own keys, sign it with them,
// and take the DID over. Authority always comes from the operation being built on.
//
// The order of the list is a ranking, and it is what makes recovery possible. A key may
// nullify operations signed by a key below it, for 72 hours after the operation it
// nullifies:
//
//	op3 ──┬── op4        signed by B
//	      │
//	      └── op5        may nullify op4 only if signed by A, and only within 72h
//
// So a controller can keep a high-authority key in cold storage, hand a lower one to a
// service, and still undo anything that service does with it. That is the whole point of
// the ranking, and the reason [Controller.Recover] exists.
//
// # How an operation is encoded
//
// An operation is submitted and served as JSON, but neither its signature nor its
// identifier is computed over that JSON. Both are computed over DAG-CBOR.
//
// The reason is that JSON has no canonical byte form — key order, whitespace and string
// escaping are all free, so the same operation can be written many ways and no two of them
// hash alike. DAG-CBOR is deterministic by construction: one encoding per value, map keys
// sorted by encoded length then lexicographically. Everything the protocol needs to be
// stable is therefore defined over the CBOR, and the JSON is only transport.
//
// So one operation exists as three byte strings at once, and this package keeps them
// apart. Signing an operation:
//
//	State ──► wire form
//	              │
//	              │ pass 1 ──► DAG-CBOR without "sig" ──► sign ──► sig
//	              ▼
//	          wire form + sig
//	              │
//	              ├ pass 2 ──► DAG-CBOR with "sig" ──► sha-256 ─┬─► CID: the operation's identifier
//	              │                                             └─► base32, first 24 chars: the DID
//	              │                                                 (genesis operation only)
//	              │
//	              └──────────► JSON with "sig" ──────────────────► the bytes POSTed
//
// Two CBOR forms rather than one, because a signature cannot cover itself. Reading an
// operation back runs the same mill in reverse, and never trusts the bytes it was handed:
//
//	JSON from the registry ─► wire form ┬─ DAG-CBOR without "sig" ─► check the signature
//	                                    └─ DAG-CBOR with "sig" ───► recompute the CID
//
// Hashing the received JSON directly would let a registry change an operation's identity
// by reformatting it. Re-encoding is what closes that.
//
// This is why the codec exists at all, why one operation holds three byte fields instead of
// one, and why each wire struct carries a cborMap method beside its JSON tags: the two
// shapes are not always the same. In the CBOR, "prev" is a plain string rather than a
// binary CID link, and a legacy create writes it as null whatever the JSON said.
//
// # The three operation types
//
// Three formats, of which this package writes two:
//
//	plc_operation   the ordinary operation: establishes a State. Every genesis operation
//	                this package writes is one, with prev = null.
//	plc_tombstone   deactivates the DID permanently. Carries no keys and no state, so
//	                nothing can follow it — though it is itself subject to the 72 hour
//	                window, so a higher-authority key can still undo it.
//	create          the deprecated genesis format, read but never written. DIDs registered
//	                before the current format still start with one, so any client that
//	                replays history has to understand it. Its recovery key and signing key
//	                become two rotation keys, in that order, and its signing key also
//	                becomes the "atproto" verification method.
//
// # What this package trusts
//
// Every operation is built on the DID's current state, which has to be fetched from the
// registry first. By default that state is whatever the registry reports (GET
// /:did/log/last): one small response, taken on trust. [WithFullChainVerification] reads
// the DID's whole history instead and replays it — genesis hash, prev links, signatures,
// and the authority and timing of every recovery — at the cost of a response proportional
// to the length of that history.
//
// Regardless of the mode, an operation is only signed if the signer's public key is one of
// the rotation keys of the state being built on. That check is what stops a hostile
// registry from feeding a controller a state that lists the registry's own rotation keys,
// for the controller to sign into place. It does not stop a hostile registry from
// reporting a stale or fabricated state, which is what the full replay is for.
//
// One thing no mode can prove: the registry's timestamps are its own and are not covered
// by any signature. The 72 hour window is therefore checked against the registry's account
// of when things happened, which holds it to its own story rather than proving anything.
//
// [Controller.Audit] always replays in full, whatever the setting.
//
// # Key types
//
// Rotation keys must be secp256k1 or P-256, as required by the specification; see
// [WithRotationKeyPolicy]. Verification-method keys may be any type supported by the
// did:key method, restricted by [WithVerificationMethodKeyPolicy]. Both are carried inside
// an operation as did:key strings.
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
//	operation.go     one operation: its three encodings, and what it can check about itself
//	chain.go         a DID's whole history: AuditEntry, Head, and the replay rules
//
//	               the codec, which turns State into operations and back, and is the only
//	               thing that applies a key policy:
//	codec.go         the type, the parse dispatch, and the two formats written as well as
//	                 read (plc_operation, plc_tombstone)
//	codec_legacy.go  the deprecated "create" genesis format, only ever read
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
