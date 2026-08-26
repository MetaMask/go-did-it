package multikey

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/MetaMask/go-did-it"
	"github.com/MetaMask/go-did-it/crypto"
	methods "github.com/MetaMask/go-did-it/verifiers/_methods"
)

// Specification: https://www.w3.org/TR/cid-1.0/#Multikey

const (
	// This is apparently the right context despite the spec above saying otherwise.
	JsonLdContext = "https://w3id.org/security/multikey/v1"
	Type          = "Multikey"
)

func init() {
	methods.Register(Type, func(data []byte, ks *crypto.KeySet) (did.VerificationMethod, error) {
		return FromJSON(data, ks)
	})
}

var _ did.VerificationMethodSignature = &MultiKey{}
var _ did.VerificationMethodKeyAgreement = &MultiKey{}

type MultiKey struct {
	id         string
	pubkey     crypto.PublicKey
	controller string
}

func NewMultiKey(id string, pubkey crypto.PublicKey, controller did.DID) *MultiKey {
	return &MultiKey{
		id:         id,
		pubkey:     pubkey,
		controller: controller.String(),
	}
}

// FromJSON decodes a Multikey verification method from JSON. As the key algorithm is only
// known at decode time, ks is used to both decode the publicKeyMultibase field and control
// which algorithms are accepted. If ks is nil, crypto.DefaultKeySet is used.
func FromJSON(data []byte, ks *crypto.KeySet) (*MultiKey, error) {
	if ks == nil {
		ks = crypto.DefaultKeySet
	}
	aux := struct {
		ID                 string `json:"id"`
		Type               string `json:"type"`
		Controller         string `json:"controller"`
		PublicKeyMultibase string `json:"publicKeyMultibase"`
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
	pub, err := ks.PublicKeyFromMultibase(aux.PublicKeyMultibase)
	if err != nil {
		return nil, fmt.Errorf("invalid publicKeyMultibase: %w", err)
	}
	return &MultiKey{id: aux.ID, pubkey: pub, controller: aux.Controller}, nil
}

func (m MultiKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID                 string `json:"id"`
		Type               string `json:"type"`
		Controller         string `json:"controller"`
		PublicKeyMultibase string `json:"publicKeyMultibase"`
	}{
		ID:                 m.ID(),
		Type:               m.Type(),
		Controller:         m.Controller(),
		PublicKeyMultibase: m.pubkey.ToPublicKeyMultibase(),
	})
}

func (m MultiKey) ID() string {
	return m.id
}

func (m MultiKey) Type() string {
	return Type
}

func (m MultiKey) Controller() string {
	return m.controller
}

// PublicKey returns the decoded public key.
func (m MultiKey) PublicKey() crypto.PublicKey {
	return m.pubkey
}

func (m MultiKey) JsonLdContext() string {
	return JsonLdContext
}

func (m MultiKey) VerifyBytes(data []byte, sig []byte, opts ...crypto.SigningOption) (bool, error) {
	if pub, ok := m.pubkey.(crypto.PublicKeySigningBytes); ok {
		return pub.VerifyBytes(data, sig, opts...), nil
	}
	return false, errors.New("not a signing public key")
}

func (m MultiKey) VerifyASN1(data []byte, sig []byte, opts ...crypto.SigningOption) (bool, error) {
	if pub, ok := m.pubkey.(crypto.PublicKeySigningASN1); ok {
		return pub.VerifyASN1(data, sig, opts...), nil
	}
	return false, errors.New("not a signing public key")
}

func (m MultiKey) PrivateKeyIsCompatible(local crypto.PrivateKeyKeyExchange) bool {
	return local.PublicKeyIsCompatible(m.pubkey)
}

func (m MultiKey) KeyExchange(local crypto.PrivateKeyKeyExchange) ([]byte, error) {
	return local.KeyExchange(m.pubkey)
}
