package x25519vm

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/MetaMask/go-did-it"
	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/x25519"
	methods "github.com/MetaMask/go-did-it/verifiers/_methods"
)

// Specification: https://w3c-ccg.github.io/did-method-key/#ed25519-x25519

const (
	JsonLdContext2020 = "https://w3id.org/security/suites/x25519-2020/v1"
	Type2020          = "X25519KeyAgreementKey2020"
)

func init() {
	methods.Register(Type2020, func(data []byte, kp *crypto.KeyPolicy) (did.VerificationMethod, error) {
		return NewKeyAgreementKey2020FromJSON(data, kp)
	})
}

var _ did.VerificationMethodKeyAgreement = &KeyAgreementKey2020{}

type KeyAgreementKey2020 struct {
	id         string
	pubkey     *x25519.PublicKey
	controller string
}

func NewKeyAgreementKey2020(id string, pubkey *x25519.PublicKey, controller did.DID) *KeyAgreementKey2020 {
	return &KeyAgreementKey2020{
		id:         id,
		pubkey:     pubkey,
		controller: controller.String(),
	}
}

// NewKeyAgreementKey2020FromJSON decodes an X25519KeyAgreementKey2020 verification method from
// JSON, using kp to decode and accept the publicKeyMultibase field. If kp is nil,
// crypto.DefaultKeyPolicy is used.
func NewKeyAgreementKey2020FromJSON(data []byte, kp *crypto.KeyPolicy) (*KeyAgreementKey2020, error) {
	if kp == nil {
		kp = crypto.DefaultKeyPolicy
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
	if aux.Type != Type2020 {
		return nil, errors.New("invalid type")
	}
	if len(aux.ID) == 0 {
		return nil, errors.New("invalid id")
	}
	if !did.HasValidDIDSyntax(aux.Controller) {
		return nil, errors.New("invalid controller")
	}
	pub, err := kp.PublicKeyFromMultibase(aux.PublicKeyMultibase)
	if err != nil {
		return nil, fmt.Errorf("invalid publicKeyMultibase: %w", err)
	}
	pubkey, ok := pub.(*x25519.PublicKey)
	if !ok {
		return nil, errors.New("publicKeyMultibase is not an X25519 key")
	}
	return &KeyAgreementKey2020{id: aux.ID, pubkey: pubkey, controller: aux.Controller}, nil
}

func (k KeyAgreementKey2020) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID                 string `json:"id"`
		Type               string `json:"type"`
		Controller         string `json:"controller"`
		PublicKeyMultibase string `json:"publicKeyMultibase"`
	}{
		ID:                 k.ID(),
		Type:               k.Type(),
		Controller:         k.Controller(),
		PublicKeyMultibase: k.pubkey.ToPublicKeyMultibase(),
	})
}

// UnmarshalJSON always fails: decoding needs a crypto.KeyPolicy. See methods.ErrDirectUnmarshal.
func (k KeyAgreementKey2020) UnmarshalJSON([]byte) error {
	return fmt.Errorf("%w: use x25519vm.NewKeyAgreementKey2020FromJSON", methods.ErrDirectUnmarshal)
}

func (k KeyAgreementKey2020) ID() string {
	return k.id
}

func (k KeyAgreementKey2020) Type() string {
	return Type2020
}

func (k KeyAgreementKey2020) Controller() string {
	return k.controller
}

func (k KeyAgreementKey2020) JsonLdContext() string {
	return JsonLdContext2020
}

func (k KeyAgreementKey2020) PrivateKeyIsCompatible(local crypto.PrivateKeyKeyExchange) bool {
	return local.PublicKeyIsCompatible(k.pubkey)
}

func (k KeyAgreementKey2020) KeyExchange(local crypto.PrivateKeyKeyExchange) ([]byte, error) {
	return local.KeyExchange(k.pubkey)
}
