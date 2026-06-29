package did_plc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MetaMask/go-did-it/controller/did-plc/internal/dagcbor"
	"github.com/MetaMask/go-did-it/crypto"
)

// Signer can produce raw-bytes ECDSA signatures. Any key that implements
// crypto.PrivateKeySigningBytes satisfies this interface directly.
//
// did:plc requires low-S signatures; this package always passes
// crypto.WithEcdsaLowSSig() when calling SignToBytes.
type Signer interface {
	SignToBytes(message []byte, opts ...crypto.SigningOption) ([]byte, error)
}

// Op holds the document content of a did:plc operation.
type Op struct {
	RotationKeys        []crypto.PublicKey
	VerificationMethods map[string]crypto.PublicKey
	AlsoKnownAs         []string
	Services            map[string]Service
}

// Service is a did:plc service endpoint.
type Service struct {
	Type     string `json:"type"`
	Endpoint string `json:"endpoint"`
}

// sign validates op and produces a fully encoded preparedOp.
// prevCID is nil for a genesis operation.
func (op Op) sign(r *Registry, signer Signer, prevCID *string) (*preparedOp, error) {
	if prevCID != nil {
		if err := validateCID(*prevCID); err != nil {
			return nil, fmt.Errorf("invalid prevCID: %w", err)
		}
	}
	if err := r.validateRotationKeys(op.RotationKeys); err != nil {
		return nil, err
	}
	if len(op.VerificationMethods) > 10 {
		return nil, fmt.Errorf("verificationMethods: at most 10 entries allowed, got %d", len(op.VerificationMethods))
	}

	rotKeys := make([]string, len(op.RotationKeys))
	for i, k := range op.RotationKeys {
		rotKeys[i] = "did:key:" + k.ToPublicKeyMultibase()
	}
	vms := make(map[string]string, len(op.VerificationMethods))
	for name, k := range op.VerificationMethods {
		vms[name] = "did:key:" + k.ToPublicKeyMultibase()
	}

	m, err := opCBORMap(rotKeys, vms, op.AlsoKnownAs, op.Services, prevCID)
	if err != nil {
		return nil, err
	}
	unsignedBytes, err := dagcbor.Encode(m)
	if err != nil {
		return nil, err
	}
	sig, err := signToBase64URL(signer, unsignedBytes)
	if err != nil {
		return nil, err
	}
	m["sig"] = sig
	signedBytes, err := dagcbor.Encode(m)
	if err != nil {
		return nil, err
	}
	jsonBytes, err := json.Marshal(opJSON{
		Type:                "plc_operation",
		RotationKeys:        rotKeys,
		VerificationMethods: vms,
		AlsoKnownAs:         op.AlsoKnownAs,
		Services:            op.Services,
		Prev:                prevCID,
		Sig:                 sig,
	})
	if err != nil {
		return nil, err
	}
	return &preparedOp{
		unsigned:  unsignedBytes,
		signed:    signedBytes,
		jsonBytes: jsonBytes,
		rotKeys:   rotKeys,
		prevCID:   prevCID,
		signature: sig,
	}, nil
}

// preparedOp is a fully signed plc_operation carrying precomputed encodings.
type preparedOp struct {
	unsigned  []byte // unsigned DAG-CBOR: used to verify the signature
	signed    []byte // signed DAG-CBOR: used to compute/verify the CID
	jsonBytes []byte // JSON wire format: submitted to the registry
	rotKeys   []string
	prevCID   *string
	signature string
}

// buildPreparedOp encodes raw (already-parsed) opJSON into CBOR and returns a preparedOp.
// jsonBytes is the original JSON, stored verbatim for MarshalJSON.
func buildPreparedOp(raw opJSON, jsonBytes json.RawMessage) (*preparedOp, error) {
	m, err := opCBORMap(raw.RotationKeys, raw.VerificationMethods, raw.AlsoKnownAs, raw.Services, raw.Prev)
	if err != nil {
		return nil, fmt.Errorf("building CBOR map: %w", err)
	}
	unsignedBytes, err := dagcbor.Encode(m)
	if err != nil {
		return nil, err
	}
	m["sig"] = raw.Sig
	signedBytes, err := dagcbor.Encode(m)
	if err != nil {
		return nil, err
	}
	return &preparedOp{
		unsigned:  unsignedBytes,
		signed:    signedBytes,
		jsonBytes: jsonBytes,
		rotKeys:   raw.RotationKeys,
		prevCID:   raw.Prev,
		signature: raw.Sig,
	}, nil
}

func parseSignedOp(data json.RawMessage) (*preparedOp, error) {
	var raw opJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if raw.Type != "plc_operation" {
		return nil, fmt.Errorf("expected type %q, got %q", "plc_operation", raw.Type)
	}
	return buildPreparedOp(raw, data)
}

func (s *preparedOp) MarshalJSON() ([]byte, error) { return s.jsonBytes, nil }

func (s *preparedOp) deriveID() (string, error) {
	if s.prevCID != nil {
		return "", fmt.Errorf("deriveID requires a genesis operation (prevCID must be nil)")
	}
	return deriveMSI(s.signed), nil
}

// opFromJSON converts the JSON fields of a plc_operation into a public Op,
// decoding did:key strings into crypto.PublicKey values.
func opFromJSON(raw opJSON) (*Op, error) {
	rotKeys := make([]crypto.PublicKey, len(raw.RotationKeys))
	for i, dk := range raw.RotationKeys {
		pub, err := didKeyToPublicKey(dk)
		if err != nil {
			return nil, fmt.Errorf("rotation key %d: %w", i, err)
		}
		rotKeys[i] = pub
	}
	vms := make(map[string]crypto.PublicKey, len(raw.VerificationMethods))
	for name, dk := range raw.VerificationMethods {
		pub, err := didKeyToPublicKey(dk)
		if err != nil {
			return nil, fmt.Errorf("verification method %q: %w", name, err)
		}
		vms[name] = pub
	}
	return &Op{
		RotationKeys:        rotKeys,
		VerificationMethods: vms,
		AlsoKnownAs:         raw.AlsoKnownAs,
		Services:            raw.Services,
	}, nil
}

func opCBORMap(rotKeys []string, vms map[string]string, akas []string, svcs map[string]Service, prevCID *string) (map[string]any, error) {
	svcsAny := make(map[string]any, len(svcs))
	for id, svc := range svcs {
		svcsAny[id] = map[string]any{"type": svc.Type, "endpoint": svc.Endpoint}
	}
	m := map[string]any{
		"type":                "plc_operation",
		"rotationKeys":        rotKeys,
		"verificationMethods": vms,
		"alsoKnownAs":         akas,
		"services":            svcsAny,
	}
	// Per the spec, prev is string-encoded in DAG-CBOR, not a binary CID link.
	if prevCID == nil {
		m["prev"] = nil
	} else {
		m["prev"] = *prevCID
	}
	return m, nil
}

func didKeyToPublicKey(didKey string) (crypto.PublicKey, error) {
	const prefix = "did:key:"
	if !strings.HasPrefix(didKey, prefix) {
		return nil, fmt.Errorf("not a did:key: %q", didKey)
	}
	return crypto.DefaultKeySet.PublicKeyFromMultibase(didKey[len(prefix):])
}

func signToBase64URL(signer Signer, message []byte) (string, error) {
	rawSig, err := signer.SignToBytes(message, crypto.WithEcdsaLowSSig())
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(rawSig), nil
}

type opJSON struct {
	Type                string             `json:"type"`
	RotationKeys        []string           `json:"rotationKeys"`
	VerificationMethods map[string]string  `json:"verificationMethods"`
	AlsoKnownAs         []string           `json:"alsoKnownAs"`
	Services            map[string]Service `json:"services"`
	Prev                *string            `json:"prev"`
	Sig                 string             `json:"sig"`
}
