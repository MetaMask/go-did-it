package didplcctl

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MetaMask/go-did-it/crypto"
)

// The codec for the deprecated "create" genesis format, still present in the history of
// DIDs registered before the current one. It can be read but never written.
// Specification: https://web.plc.directory/spec/v0.1/did-plc (Legacy operations)

// legacyCreateJSON is a legacy genesis operation as it appears on the wire.
//
// Field key ordering in DAG-CBOR (canonical by encoded length, then lexicographic):
// "sig"(3) < "prev"(4) < "type"(4,lex) < "handle"(6) < "service"(7) < "signingKey"(10) < "recoveryKey"(11)
type legacyCreateJSON struct {
	Type        string  `json:"type"`
	SigningKey  string  `json:"signingKey"`
	RecoveryKey string  `json:"recoveryKey"`
	Handle      string  `json:"handle"`
	Service     string  `json:"service"`
	Prev        *string `json:"prev"`
	Sig         string  `json:"sig"`
}

// cborMap returns the DAG-CBOR form of the operation, without "sig". prev is always null:
// a legacy create is by definition a genesis operation.
func (l legacyCreateJSON) cborMap() map[string]any {
	return map[string]any{
		"type":        typeLegacyCreate,
		"signingKey":  l.SigningKey,
		"recoveryKey": l.RecoveryKey,
		"handle":      l.Handle,
		"service":     l.Service,
		"prev":        nil,
	}
}

// parseLegacyCreate decodes a legacy create operation and normalizes it to the current
// format, exactly as the registry does: the recovery key and the signing key become the
// rotation keys, in that order, and the signing key also becomes the "atproto"
// verification method.
func (r *Registry) parseLegacyCreate(data json.RawMessage) (*preparedOp, error) {
	var raw legacyCreateJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("legacy create: %w", err)
	}
	if raw.Type != typeLegacyCreate {
		return nil, fmt.Errorf("expected type %q, got %q", typeLegacyCreate, raw.Type)
	}
	if raw.Prev != nil {
		return nil, fmt.Errorf("legacy create operation with non-null prev %q", *raw.Prev)
	}
	enc, err := buildEncodings(raw.cborMap(), raw.Sig)
	if err != nil {
		return nil, err
	}

	rotKeys, err := r.rotationKeysFromWire([]string{raw.RecoveryKey, raw.SigningKey})
	if err != nil {
		return nil, fmt.Errorf("legacy create: %w", err)
	}
	// The signing key is both a rotation key and the atproto verification method, so it
	// has to pass both policies.
	signingVMPub, err := didKeyToPublicKey(r.vmPolicy, raw.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("legacy create signingKey as verification method: %w", err)
	}

	return &preparedOp{
		encodings: enc,
		jsonBytes: data,
		rotKeys:   rotKeys,
		op: &Op{
			RotationKeys:        publicKeys(rotKeys),
			VerificationMethods: map[string]crypto.PublicKey{"atproto": signingVMPub},
			AlsoKnownAs:         []string{ensureAtprotoPrefix(raw.Handle)},
			Services: map[string]Service{
				"atproto_pds": {Type: "AtprotoPersonalDataServer", Endpoint: ensureHTTPPrefix(raw.Service)},
			},
		},
	}, nil
}

// ensureAtprotoPrefix mirrors the registry's normalization of a legacy handle.
func ensureAtprotoPrefix(s string) string {
	if strings.HasPrefix(s, "at://") {
		return s
	}
	// Matches the reference implementation, which strips one occurrence of each.
	s = strings.Replace(s, "http://", "", 1)
	s = strings.Replace(s, "https://", "", 1)
	return "at://" + s
}

// ensureHTTPPrefix mirrors the registry's normalization of a legacy service endpoint.
func ensureHTTPPrefix(s string) string {
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return s
	}
	return "https://" + s
}
