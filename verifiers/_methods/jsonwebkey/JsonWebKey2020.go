package jsonwebkey

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/MetaMask/go-did-it"
	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/jwk"
	methods "github.com/MetaMask/go-did-it/verifiers/_methods"
)

// Specification:
// - https://www.w3.org/TR/vc-jws-2020/
// - https://w3c-ccg.github.io/lds-jws2020/

const (
	JsonLdContext = "https://w3id.org/security/suites/jws-2020/v1"
	Type          = "JsonWebKey2020"
)

func init() {
	methods.Register(Type, func(data []byte, ks *crypto.KeySet) (did.VerificationMethod, error) {
		return FromJSON(data, ks)
	})
}

var _ did.VerificationMethodSignature = &JsonWebKey2020{}
var _ did.VerificationMethodKeyAgreement = &JsonWebKey2020{}

type JsonWebKey2020 struct {
	id         string
	pubkey     crypto.PublicKey
	controller string
}

func NewJsonWebKey2020(id string, pubkey crypto.PublicKey, controller did.DID) *JsonWebKey2020 {
	return &JsonWebKey2020{
		id:         id,
		pubkey:     pubkey,
		controller: controller.String(),
	}
}

func (j JsonWebKey2020) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID           string        `json:"id"`
		Type         string        `json:"type"`
		Controller   string        `json:"controller"`
		PublicKeyJWK jwk.PublicJwk `json:"publicKeyJwk"`
	}{
		ID:           j.ID(),
		Type:         j.Type(),
		Controller:   j.Controller(),
		PublicKeyJWK: jwk.PublicJwk{Pubkey: j.pubkey},
	})
}

// FromJSON decodes a JsonWebKey2020 verification method from JSON, using ks to decode
// and accept the publicKeyJwk field. If ks is nil, crypto.DefaultKeySet is used.
func FromJSON(data []byte, ks *crypto.KeySet) (*JsonWebKey2020, error) {
	aux := struct {
		ID           string          `json:"id"`
		Type         string          `json:"type"`
		Controller   string          `json:"controller"`
		PublicKeyJWK json.RawMessage `json:"publicKeyJwk"`
	}{}
	if err := json.Unmarshal(data, &aux); err != nil {
		return nil, err
	}
	if aux.Type != Type {
		return nil, errors.New("invalid type")
	}
	if len(aux.ID) == 0 {
		return nil, errors.New("invalid id")
	}
	if !did.HasValidDIDSyntax(aux.Controller) {
		return nil, errors.New("invalid controller")
	}
	if len(aux.PublicKeyJWK) == 0 {
		return nil, errors.New("missing publicKeyJwk")
	}
	pj, err := jwk.PublicFromJSON(aux.PublicKeyJWK, ks)
	if err != nil {
		return nil, fmt.Errorf("invalid publicKeyJwk: %w", err)
	}
	return &JsonWebKey2020{id: aux.ID, pubkey: pj.Pubkey, controller: aux.Controller}, nil
}

func (j JsonWebKey2020) ID() string {
	return j.id
}

func (j JsonWebKey2020) Type() string {
	return Type
}

func (j JsonWebKey2020) Controller() string {
	return j.controller
}

// PublicKey returns the decoded public key.
func (j JsonWebKey2020) PublicKey() crypto.PublicKey {
	return j.pubkey
}

func (j JsonWebKey2020) JsonLdContext() string {
	return JsonLdContext
}

func (j JsonWebKey2020) VerifyBytes(data []byte, sig []byte, opts ...crypto.SigningOption) (bool, error) {
	if pub, ok := j.pubkey.(crypto.PublicKeySigningBytes); ok {
		return pub.VerifyBytes(data, sig, opts...), nil
	}
	return false, errors.New("not a signing public key")
}

func (j JsonWebKey2020) VerifyASN1(data []byte, sig []byte, opts ...crypto.SigningOption) (bool, error) {
	if pub, ok := j.pubkey.(crypto.PublicKeySigningASN1); ok {
		return pub.VerifyASN1(data, sig, opts...), nil
	}
	return false, errors.New("not a signing public key")
}

func (j JsonWebKey2020) PrivateKeyIsCompatible(local crypto.PrivateKeyKeyExchange) bool {
	return local.PublicKeyIsCompatible(j.pubkey)
}

func (j JsonWebKey2020) KeyExchange(local crypto.PrivateKeyKeyExchange) ([]byte, error) {
	return local.KeyExchange(j.pubkey)
}
