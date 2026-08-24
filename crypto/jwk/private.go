package jwk

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/MetaMask/go-did-it/crypto"
)

// PrivateJwk is a JWK holding a private key
type PrivateJwk struct {
	Privkey crypto.PrivateKey
	Kid     string // optional
	Use     string // optional; "sig" or "enc" per RFC 7517 §4.2
}

func (pj PrivateJwk) MarshalJSON() ([]byte, error) {
	enc, ok := pj.Privkey.(interface{ JwkParams() map[string]string })
	if !ok {
		return nil, fmt.Errorf("unsupported key type %T", pj.Privkey)
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

func (pj *PrivateJwk) UnmarshalJSON(bytes []byte) error {
	res, err := PrivateFromJSON(bytes, nil)
	if err != nil {
		return err
	}
	*pj = *res
	return nil
}

// PrivateFromJSON decodes a private key JWK, accepting only key algorithms in ks.
// If ks is nil, crypto.DefaultKeySet is used.
func PrivateFromJSON(data []byte, ks *crypto.KeySet) (*PrivateJwk, error) {
	if ks == nil {
		ks = crypto.DefaultKeySet
	}
	aux := make(map[string]string)
	if err := json.Unmarshal(data, &aux); err != nil {
		return nil, err
	}
	kt, ok := ks.KeyTypeForJwk(aux["kty"], aux["crv"])
	if !ok {
		return nil, fmt.Errorf("%w: JWK kty %q crv %q not in the key set", crypto.ErrKeyNotAccepted, aux["kty"], aux["crv"])
	}
	if kt.DecodeJwkPrivate == nil {
		return nil, fmt.Errorf("%w: private JWK decoding not supported for %s", crypto.ErrKeyNotAccepted, kt.Name)
	}
	params, err := decodeParams(aux)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", crypto.ErrInvalidKey, err)
	}
	priv, err := kt.DecodeJwkPrivate(params)
	if err != nil {
		if errors.Is(err, crypto.ErrKeyNotAccepted) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", crypto.ErrInvalidKey, err)
	}
	return &PrivateJwk{Privkey: priv, Kid: aux["kid"], Use: aux["use"]}, nil
}
