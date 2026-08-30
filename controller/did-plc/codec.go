package didplcctl

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/MetaMask/go-did-it/controller/did-plc/internal/dagcbor"
	"github.com/MetaMask/go-did-it/crypto"
)

// codec converts between [State] and the wire form of an operation, in both directions,
// and is where this package's configuration stops: a key policy is consulted where
// did:key strings are encoded and decoded, and nowhere else. That is what leaves the
// protocol rules in chain.go needing no configuration of their own — by the time an
// operation reaches them, its keys are keys.
//
// The codec spans two files, one per direction of travel. This one carries the formats
// this package both reads and writes — plc_operation and plc_tombstone — along with the
// type itself and the parse dispatch that reaches all three. legacy.go carries the third,
// the deprecated "create" genesis format, which is only ever read.
type codec struct {
	// rotationPolicy is the algorithms accepted for rotation keys, vmPolicy those
	// accepted for verification methods.
	rotationPolicy *crypto.KeyPolicy
	vmPolicy       *crypto.KeyPolicy
}

// Converting a caller-supplied State to its wire form, checking it against the limits in
// spec.go on the way. Each of these turns what would otherwise be an opaque HTTP 400 from
// the registry into a local error.

// rotationKeysToWire validates a caller's rotation key list and converts it.
func (c *codec) rotationKeysToWire(keys []crypto.PublicKey) ([]rotationKey, error) {
	if len(keys) < minRotationKeys || len(keys) > maxRotationKeys {
		return nil, fmt.Errorf("rotation keys: need %d to %d keys, got %d", minRotationKeys, maxRotationKeys, len(keys))
	}
	out := make([]rotationKey, len(keys))
	seen := make(map[string]int, len(keys))
	for i, key := range keys {
		if key == nil {
			return nil, fmt.Errorf("rotation key %d is nil", i)
		}
		if err := c.rotationPolicy.CheckKey(key); err != nil {
			return nil, fmt.Errorf("rotation key %d: %w", i, err)
		}
		verifier, ok := key.(crypto.PublicKeySigningBytes)
		if !ok {
			return nil, fmt.Errorf("rotation key %d: %T cannot verify raw signatures", i, key)
		}
		dk := didKeyString(key)
		if j, dup := seen[dk]; dup {
			return nil, fmt.Errorf("rotation keys %d and %d are the same key: the specification forbids duplicates", j, i)
		}
		seen[dk] = i
		out[i] = rotationKey{didKey: dk, pub: verifier}
	}
	return out, nil
}

// verificationMethodsToWire validates a caller's verification methods and converts them.
// The keys are checked against the policy on the way out as well as on the way in, so a
// key this package hands out is always one it would accept back.
func (c *codec) verificationMethodsToWire(vms map[string]crypto.PublicKey) (map[string]string, error) {
	if len(vms) > maxVerificationMethods {
		return nil, fmt.Errorf("verificationMethods: at most %d entries allowed, got %d", maxVerificationMethods, len(vms))
	}
	out := make(map[string]string, len(vms))
	for name, key := range vms {
		if err := validateName("verification method", name); err != nil {
			return nil, err
		}
		if key == nil {
			return nil, fmt.Errorf("verification method %q is nil", name)
		}
		if err := c.vmPolicy.CheckKey(key); err != nil {
			return nil, fmt.Errorf("verification method %q: %w", name, err)
		}
		out[name] = didKeyString(key)
	}
	return out, nil
}

// Converting the wire form back. Rotation keys go through the rotation key policy and
// verification methods through the verification method policy.

// rotationKeyFromWire decodes one rotation key.
func (c *codec) rotationKeyFromWire(didKey string) (rotationKey, error) {
	pub, err := didKeyToPublicKey(c.rotationPolicy, didKey)
	if err != nil {
		return rotationKey{}, err
	}
	verifier, ok := pub.(crypto.PublicKeySigningBytes)
	if !ok {
		return rotationKey{}, fmt.Errorf("%T cannot verify raw signatures", pub)
	}
	return rotationKey{didKey: didKey, pub: verifier}, nil
}

// rotationKeysFromWire decodes an operation's rotation key list.
func (c *codec) rotationKeysFromWire(didKeys []string) ([]rotationKey, error) {
	out := make([]rotationKey, len(didKeys))
	for i, dk := range didKeys {
		k, err := c.rotationKeyFromWire(dk)
		if err != nil {
			return nil, fmt.Errorf("rotation key %d: %w", i, err)
		}
		out[i] = k
	}
	return out, nil
}

// verificationMethodsFromWire decodes an operation's verification methods.
func (c *codec) verificationMethodsFromWire(vms map[string]string) (map[string]crypto.PublicKey, error) {
	out := make(map[string]crypto.PublicKey, len(vms))
	for name, dk := range vms {
		pub, err := didKeyToPublicKey(c.vmPolicy, dk)
		if err != nil {
			return nil, fmt.Errorf("verification method %q: %w", name, err)
		}
		out[name] = pub
	}
	return out, nil
}

// signing

// signGenesis builds and signs the genesis operation of a new DID.
func (c *codec) signGenesis(state State, signer Signer) (*operation, error) {
	w, rotKeys, err := c.toWire(state, nil)
	if err != nil {
		return nil, err
	}
	// A genesis operation is self-signed: its own rotation keys are the only authority
	// available, there being no earlier operation to grant one.
	if err := checkSignerAuthorized(signer, rotKeys); err != nil {
		return nil, err
	}
	return signWireOp(w, state, signer, rotKeys)
}

// signUpdate builds and signs an operation replacing the state established by the
// operation at prev. authorized is the set of rotation keys allowed to sign it, which is
// that state's rotation keys for an ordinary update and a higher-authority prefix of them
// for a recovery.
func (c *codec) signUpdate(state State, signer Signer, prev string, authorized []rotationKey) (*operation, error) {
	w, rotKeys, err := c.toWire(state, &prev)
	if err != nil {
		return nil, err
	}
	// The authority comes from the state being replaced, never from the operation itself.
	if err := checkSignerAuthorized(signer, authorized); err != nil {
		return nil, err
	}
	return signWireOp(w, state, signer, rotKeys)
}

// signWireOp signs w and assembles the operation. rotKeys is w's own rotation key list,
// carried through as the authority for whatever operation comes next.
func signWireOp(w opJSON, state State, signer Signer, rotKeys []rotationKey) (*operation, error) {
	enc, err := signEncodings(w.cborMap(), signer)
	if err != nil {
		return nil, err
	}
	if len(enc.signed) > maxOperationBytes {
		return nil, fmt.Errorf("operation is %d bytes of DAG-CBOR, over the %d byte limit", len(enc.signed), maxOperationBytes)
	}
	w.Sig = enc.sig
	jsonBytes, err := json.Marshal(w)
	if err != nil {
		return nil, err
	}
	return &operation{
		encodings: enc,
		jsonBytes: jsonBytes,
		prevCID:   w.Prev,
		rotKeys:   rotKeys,
		state:     &state,
	}, nil
}

// toWire validates state against the limits the specification imposes and converts it to its
// wire form, returning its rotation keys alongside: the operation being built needs them
// as strings, and whatever is built on it will need them decoded.
func (c *codec) toWire(state State, prev *string) (opJSON, []rotationKey, error) {
	if prev != nil {
		if err := dagcbor.ValidateCID(*prev); err != nil {
			return opJSON{}, nil, fmt.Errorf("invalid prev CID: %w", err)
		}
	}
	rotKeys, err := c.rotationKeysToWire(state.RotationKeys)
	if err != nil {
		return opJSON{}, nil, err
	}
	vms, err := c.verificationMethodsToWire(state.VerificationMethods)
	if err != nil {
		return opJSON{}, nil, err
	}
	if err := validateAlsoKnownAs(state.AlsoKnownAs); err != nil {
		return opJSON{}, nil, err
	}
	if err := validateServices(state.Services); err != nil {
		return opJSON{}, nil, err
	}
	return opJSON{
		Type:                typeOperation,
		RotationKeys:        didKeys(rotKeys),
		VerificationMethods: vms,
		AlsoKnownAs:         state.AlsoKnownAs,
		Services:            state.Services,
		Prev:                prev,
	}.normalize(), rotKeys, nil
}

// parsing

// parseOp decodes any of the three operation types from its JSON wire form.
func (c *codec) parseOp(data json.RawMessage) (*operation, error) {
	// opJSON carries the type discriminator as well as every plc_operation field, so the
	// common case needs no second unmarshal.
	var fields opJSON
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	switch fields.Type {
	case typeOperation:
		return c.buildOperation(fields, data)
	case typeTombstone:
		return parseTombstone(data)
	case typeLegacyCreate:
		return c.parseLegacyCreate(data)
	case "":
		return nil, errors.New("operation has no type")
	default:
		return nil, fmt.Errorf("unknown operation type %q", fields.Type)
	}
}

// buildOperation re-encodes an already-parsed plc_operation into DAG-CBOR and decodes its
// keys. jsonBytes is kept verbatim so the operation can be resubmitted unchanged.
func (c *codec) buildOperation(raw opJSON, jsonBytes json.RawMessage) (*operation, error) {
	enc, err := buildEncodings(raw.cborMap(), raw.Sig)
	if err != nil {
		return nil, err
	}
	rotKeys, err := c.rotationKeysFromWire(raw.RotationKeys)
	if err != nil {
		return nil, err
	}
	vms, err := c.verificationMethodsFromWire(raw.VerificationMethods)
	if err != nil {
		return nil, err
	}
	return &operation{
		encodings: enc,
		jsonBytes: jsonBytes,
		prevCID:   raw.Prev,
		rotKeys:   rotKeys,
		state: &State{
			RotationKeys:        publicKeys(rotKeys),
			VerificationMethods: vms,
			AlsoKnownAs:         raw.AlsoKnownAs,
			Services:            raw.Services,
		},
	}, nil
}

// the wire form itself

// opJSON is a plc_operation as it appears on the wire, with keys as did:key strings rather
// than key objects. Both encodings are derived from it: the DAG-CBOR that is signed and
// hashed, and the JSON that is submitted.
type opJSON struct {
	Type                string             `json:"type"`
	RotationKeys        []string           `json:"rotationKeys"`
	VerificationMethods map[string]string  `json:"verificationMethods"`
	AlsoKnownAs         []string           `json:"alsoKnownAs"`
	Services            map[string]Service `json:"services"`
	Prev                *string            `json:"prev"`
	Sig                 string             `json:"sig"`
}

// normalize fills in the empty collections, so that they marshal as [] and {} rather than
// null. The registry's schema requires an array and two objects and rejects null outright,
// and the DAG-CBOR being signed encodes them as an empty array and empty maps, so null on
// the wire would also disagree with the CID that was computed.
func (o opJSON) normalize() opJSON {
	if o.RotationKeys == nil {
		o.RotationKeys = []string{}
	}
	if o.VerificationMethods == nil {
		o.VerificationMethods = map[string]string{}
	}
	if o.AlsoKnownAs == nil {
		o.AlsoKnownAs = []string{}
	}
	if o.Services == nil {
		o.Services = map[string]Service{}
	}
	return o
}

// cborMap returns the DAG-CBOR form of the operation, without "sig".
func (o opJSON) cborMap() map[string]any {
	svcs := make(map[string]any, len(o.Services))
	for id, svc := range o.Services {
		svcs[id] = map[string]any{"type": svc.Type, "endpoint": svc.Endpoint}
	}
	m := map[string]any{
		"type":                typeOperation,
		"rotationKeys":        o.RotationKeys,
		"verificationMethods": o.VerificationMethods,
		"alsoKnownAs":         o.AlsoKnownAs,
		"services":            svcs,
	}
	// Per the spec, prev is string-encoded in DAG-CBOR, not a binary CID link.
	if o.Prev == nil {
		m["prev"] = nil
	} else {
		m["prev"] = *o.Prev
	}
	return m
}

// The codec for plc_tombstone, the operation that permanently deactivates a DID. It
// carries no keys and establishes no state, so the resulting operation has neither.

type tombstoneJSON struct {
	Type string `json:"type"`
	Prev string `json:"prev"`
	Sig  string `json:"sig"`
}

// cborMap returns the DAG-CBOR form of the tombstone, without "sig". prev is
// string-encoded per the spec, not a binary CID link, and is not nullable.
func (t tombstoneJSON) cborMap() map[string]any {
	return map[string]any{"type": typeTombstone, "prev": t.Prev}
}

// signTombstone builds the operation that deactivates a DID. authorized is the rotation
// key set of the operation being tombstoned, which bounds who may sign.
func signTombstone(signer Signer, prevCID string, authorized []rotationKey) (*operation, error) {
	if err := dagcbor.ValidateCID(prevCID); err != nil {
		return nil, fmt.Errorf("invalid prev CID: %w", err)
	}
	if err := checkSignerAuthorized(signer, authorized); err != nil {
		return nil, err
	}
	t := tombstoneJSON{Type: typeTombstone, Prev: prevCID}
	enc, err := signEncodings(t.cborMap(), signer)
	if err != nil {
		return nil, err
	}
	t.Sig = enc.sig
	jsonBytes, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}
	return &operation{encodings: enc, jsonBytes: jsonBytes, prevCID: &prevCID}, nil
}

func parseTombstone(data json.RawMessage) (*operation, error) {
	var raw tombstoneJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if raw.Type != typeTombstone {
		return nil, fmt.Errorf("expected type %q, got %q", typeTombstone, raw.Type)
	}
	if err := dagcbor.ValidateCID(raw.Prev); err != nil {
		return nil, fmt.Errorf("invalid prev CID: %w", err)
	}
	enc, err := buildEncodings(raw.cborMap(), raw.Sig)
	if err != nil {
		return nil, err
	}
	return &operation{encodings: enc, jsonBytes: data, prevCID: &raw.Prev}, nil
}
