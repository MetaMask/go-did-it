package ed25519vm

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/MetaMask/go-did-it"
	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/ed25519"
	methods "github.com/MetaMask/go-did-it/verifiers/_methods"
)

// Specification: https://w3c.github.io/cg-reports/credentials/CG-FINAL-di-eddsa-2020-20220724/

const (
	JsonLdContext2020 = "https://w3id.org/security/suites/ed25519-2020/v1"
	Type2020          = "Ed25519VerificationKey2020"
)

func init() {
	methods.Register(Type2020, func(data []byte, ks *crypto.KeySet) (did.VerificationMethod, error) {
		return VerificationKey2020FromJSON(data, ks)
	})
}

var _ did.VerificationMethodSignature = &VerificationKey2020{}

type VerificationKey2020 struct {
	id         string
	pubkey     ed25519.PublicKey
	controller string
}

func NewVerificationKey2020(id string, pubkey ed25519.PublicKey, controller did.DID) *VerificationKey2020 {
	return &VerificationKey2020{
		id:         id,
		pubkey:     pubkey,
		controller: controller.String(),
	}
}

func (v VerificationKey2020) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID                 string `json:"id"`
		Type               string `json:"type"`
		Controller         string `json:"controller"`
		PublicKeyMultibase string `json:"publicKeyMultibase"`
	}{
		ID:                 v.ID(),
		Type:               v.Type(),
		Controller:         v.Controller(),
		PublicKeyMultibase: v.pubkey.ToPublicKeyMultibase(),
	})
}

// VerificationKey2020FromJSON decodes an Ed25519VerificationKey2020 verification method from
// JSON, using ks to decode and accept the publicKeyMultibase field. If ks is nil,
// crypto.DefaultKeySet is used.
func VerificationKey2020FromJSON(data []byte, ks *crypto.KeySet) (*VerificationKey2020, error) {
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
	if aux.Type != Type2020 {
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
	pubkey, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("publicKeyMultibase is not an Ed25519 key")
	}
	return &VerificationKey2020{id: aux.ID, pubkey: pubkey, controller: aux.Controller}, nil
}

func (v VerificationKey2020) ID() string {
	return v.id
}

func (v VerificationKey2020) Type() string {
	return Type2020
}

func (v VerificationKey2020) Controller() string {
	return v.controller
}

// PublicKey returns the decoded public key.
func (v VerificationKey2020) PublicKey() crypto.PublicKey {
	return v.pubkey
}

func (v VerificationKey2020) JsonLdContext() string {
	return JsonLdContext2020
}

func (v VerificationKey2020) VerifyBytes(data []byte, sig []byte, opts ...crypto.SigningOption) (bool, error) {
	return v.pubkey.VerifyBytes(data, sig, opts...), nil
}

func (v VerificationKey2020) VerifyASN1(data []byte, sig []byte, opts ...crypto.SigningOption) (bool, error) {
	return v.pubkey.VerifyASN1(data, sig, opts...), nil
}
