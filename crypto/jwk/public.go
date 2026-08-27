package jwk

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/MetaMask/go-did-it/crypto"
)

// Specification:
// - https://www.rfc-editor.org/rfc/rfc7517#section-4 (JWK)
// - https://www.iana.org/assignments/jose/jose.xhtml#web-key-types (key parameters)

// PublicJwk is a JWK holding a public key
type PublicJwk struct {
	Pubkey crypto.PublicKey
	Kid    string // optional
	Use    string // optional; "sig" or "enc" per RFC 7517 §4.2
}

func (pj PublicJwk) MarshalJSON() ([]byte, error) {
	enc, ok := pj.Pubkey.(interface{ JwkParams() map[string]string })
	if !ok {
		return nil, fmt.Errorf("unsupported key type %T", pj.Pubkey)
	}
	params := enc.JwkParams()
	if pj.Kid != "" {
		params["kid"] = pj.Kid
	}
	if pj.Use != "" {
		params["use"] = pj.Use
	}
	return json.Marshal(params)
}

func (pj *PublicJwk) UnmarshalJSON(bytes []byte) error {
	res, err := PublicFromJSON(bytes, nil)
	if err != nil {
		return err
	}
	*pj = *res
	return nil
}

// PublicFromJSON decodes a public key JWK, accepting only key algorithms in kp.
// If kp is nil, crypto.DefaultKeyPolicy is used.
func PublicFromJSON(data []byte, kp *crypto.KeyPolicy) (*PublicJwk, error) {
	if kp == nil {
		kp = crypto.DefaultKeyPolicy
	}
	aux := make(map[string]string)
	if err := json.Unmarshal(data, &aux); err != nil {
		return nil, err
	}
	kt, ok := kp.KeyTypeForJwk(aux["kty"], aux["crv"])
	if !ok {
		if len(kp.KeyTypes()) == 0 {
			return nil, fmt.Errorf("%w: the key policy is empty (register algorithms with crypto.Register, or import crypto/all)", crypto.ErrKeyNotAccepted)
		}
		return nil, fmt.Errorf("%w: JWK kty %q crv %q not in the key policy", crypto.ErrKeyNotAccepted, aux["kty"], aux["crv"])
	}
	if kt.DecodeJwkPublic == nil {
		return nil, fmt.Errorf("%w: public JWK decoding not supported for %s", crypto.ErrKeyNotAccepted, kt.Name)
	}
	params, err := decodeParams(aux)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", crypto.ErrInvalidKey, err)
	}
	pub, err := kt.DecodeJwkPublic(params)
	if err != nil {
		if errors.Is(err, crypto.ErrKeyNotAccepted) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", crypto.ErrInvalidKey, err)
	}
	return &PublicJwk{Pubkey: pub, Kid: aux["kid"], Use: aux["use"]}, nil
}

// decodeParams base64url-decodes the standard JWK key parameters.
func decodeParams(aux map[string]string) (map[string][]byte, error) {
	params := make(map[string][]byte)
	for _, name := range []string{"x", "y", "n", "e", "d", "p", "q", "dp", "dq", "qi"} {
		s, ok := aux[name]
		if !ok {
			continue
		}
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("invalid %s parameter: %w", name, err)
		}
		params[name] = b
	}
	return params, nil
}
