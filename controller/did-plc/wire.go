package didplcctl

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/MetaMask/go-did-it/controller/did-plc/internal/dagcbor"
	"github.com/MetaMask/go-did-it/crypto"
)

// The codec for plc_operation. The other two operation types are in tombstone.go and
// legacy.go; all three end up as a preparedOp.

// encodings holds the three byte-level forms of an operation, which the protocol requires
// to be kept apart: the DAG-CBOR without "sig", which is what the signature covers; the
// DAG-CBOR with it, which is what the CID is computed from; and the signature itself.
type encodings struct {
	unsigned []byte
	signed   []byte
	sig      string
}

// signEncodings signs the DAG-CBOR of m and returns the encodings of the result. m gains a
// "sig" entry.
func signEncodings(m map[string]any, signer Signer) (encodings, error) {
	unsigned, err := dagcbor.Encode(m)
	if err != nil {
		return encodings{}, err
	}
	sig, err := signToBase64URL(signer, unsigned)
	if err != nil {
		return encodings{}, err
	}
	m["sig"] = sig
	signed, err := dagcbor.Encode(m)
	if err != nil {
		return encodings{}, err
	}
	return encodings{unsigned: unsigned, signed: signed, sig: sig}, nil
}

// buildEncodings returns the encodings of an operation whose signature is already known,
// as when one is read back from the registry. m gains a "sig" entry.
func buildEncodings(m map[string]any, sig string) (encodings, error) {
	unsigned, err := dagcbor.Encode(m)
	if err != nil {
		return encodings{}, err
	}
	m["sig"] = sig
	signed, err := dagcbor.Encode(m)
	if err != nil {
		return encodings{}, err
	}
	return encodings{unsigned: unsigned, signed: signed, sig: sig}, nil
}

func signToBase64URL(signer Signer, message []byte) (string, error) {
	rawSig, err := signer.SignToBytes(message, crypto.WithEcdsaLowSSig())
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}
	// Unpadded base64url: the specification rejects a signature carrying '=' padding.
	return base64.RawURLEncoding.EncodeToString(rawSig), nil
}

// preparedOp is an operation ready to be submitted or verified: its byte encodings, plus
// the parts of it the protocol reasons about. It covers all three operation types.
type preparedOp struct {
	encodings
	// jsonBytes is the JSON wire form: submitted to the registry, or kept verbatim from it.
	jsonBytes []byte
	// prevCID is the operation this one builds on, nil only for a genesis operation.
	prevCID *string
	// rotKeys is this operation's rotation keys, normalized (a legacy create op yields its
	// recovery key then its signing key). They are the authority for the next operation.
	rotKeys []rotationKey
	// op is the document state this operation establishes.
	op *Op
}

// isTombstone reports whether this operation deactivates the DID. A tombstone carries no
// keys of its own and establishes no state, which is why op and rotKeys are nil for one.
func (p *preparedOp) isTombstone() bool { return p.op == nil }

// signing

// signGenesis builds and signs the genesis operation of a new DID.
func (r *Registry) signGenesis(op Op, signer Signer) (*preparedOp, error) {
	w, rotKeys, err := r.toWire(op, nil)
	if err != nil {
		return nil, err
	}
	// A genesis operation is self-signed: its own rotation keys are the only authority
	// available, there being no earlier operation to grant one.
	if err := checkSignerAuthorized(signer, rotKeys); err != nil {
		return nil, err
	}
	return signWireOp(w, op, signer, rotKeys)
}

// signUpdate builds and signs an operation replacing the state established by the
// operation at prev. authorized is the set of rotation keys allowed to sign it, which is
// that state's rotation keys for an ordinary update and a higher-authority prefix of them
// for a recovery.
func (r *Registry) signUpdate(op Op, signer Signer, prev string, authorized []rotationKey) (*preparedOp, error) {
	w, rotKeys, err := r.toWire(op, &prev)
	if err != nil {
		return nil, err
	}
	// The authority comes from the state being replaced, never from the operation itself.
	if err := checkSignerAuthorized(signer, authorized); err != nil {
		return nil, err
	}
	return signWireOp(w, op, signer, rotKeys)
}

// signWireOp signs w and assembles the operation. rotKeys is w's own rotation key list,
// carried through as the authority for whatever operation comes next.
func signWireOp(w opJSON, op Op, signer Signer, rotKeys []rotationKey) (*preparedOp, error) {
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
	return &preparedOp{
		encodings: enc,
		jsonBytes: jsonBytes,
		prevCID:   w.Prev,
		rotKeys:   rotKeys,
		op:        &op,
	}, nil
}

// toWire validates op against the limits the specification imposes and converts it to its
// wire form, returning its rotation keys alongside: the operation being built needs them
// as strings, and whatever is built on it will need them decoded.
func (r *Registry) toWire(op Op, prev *string) (opJSON, []rotationKey, error) {
	if prev != nil {
		if err := validateCID(*prev); err != nil {
			return opJSON{}, nil, fmt.Errorf("invalid prev CID: %w", err)
		}
	}
	rotKeys, err := r.rotationKeysToWire(op.RotationKeys)
	if err != nil {
		return opJSON{}, nil, err
	}
	vms, err := r.verificationMethodsToWire(op.VerificationMethods)
	if err != nil {
		return opJSON{}, nil, err
	}
	if err := validateAlsoKnownAs(op.AlsoKnownAs); err != nil {
		return opJSON{}, nil, err
	}
	if err := validateServices(op.Services); err != nil {
		return opJSON{}, nil, err
	}
	return opJSON{
		Type:                typeOperation,
		RotationKeys:        didKeys(rotKeys),
		VerificationMethods: vms,
		AlsoKnownAs:         op.AlsoKnownAs,
		Services:            op.Services,
		Prev:                prev,
	}.normalized(), rotKeys, nil
}

// parsing

// parseOp decodes any of the three operation types from its JSON wire form.
func (r *Registry) parseOp(data json.RawMessage) (*preparedOp, error) {
	// opJSON carries the type discriminator as well as every plc_operation field, so the
	// common case needs no second unmarshal.
	var fields opJSON
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	switch fields.Type {
	case typeOperation:
		return r.buildOperation(fields, data)
	case typeTombstone:
		return parseTombstone(data)
	case typeLegacyCreate:
		return r.parseLegacyCreate(data)
	case "":
		return nil, errors.New("operation has no type")
	default:
		return nil, fmt.Errorf("unknown operation type %q", fields.Type)
	}
}

// buildOperation re-encodes an already-parsed plc_operation into DAG-CBOR and decodes its
// keys. jsonBytes is kept verbatim so the operation can be resubmitted unchanged.
func (r *Registry) buildOperation(raw opJSON, jsonBytes json.RawMessage) (*preparedOp, error) {
	enc, err := buildEncodings(raw.cborMap(), raw.Sig)
	if err != nil {
		return nil, err
	}
	rotKeys, err := r.rotationKeysFromWire(raw.RotationKeys)
	if err != nil {
		return nil, err
	}
	vms, err := r.verificationMethodsFromWire(raw.VerificationMethods)
	if err != nil {
		return nil, err
	}
	return &preparedOp{
		encodings: enc,
		jsonBytes: jsonBytes,
		prevCID:   raw.Prev,
		rotKeys:   rotKeys,
		op: &Op{
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

// normalized fills in the empty collections, so that they marshal as [] and {} rather than
// null. The registry's schema requires an array and two objects and rejects null outright,
// and the DAG-CBOR being signed encodes them as an empty array and empty maps, so null on
// the wire would also disagree with the CID that was computed.
func (o opJSON) normalized() opJSON {
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
