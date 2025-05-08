package x25519

import (
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/INFURA/go-did"
)

// Specification: https://w3c-ccg.github.io/did-method-key/#ed25519-x25519

const (
	MultibaseCode = uint64(0xec)
	JsonLdContext = "https://w3id.org/security/suites/x25519-2020/v1"
	Type          = "X25519KeyAgreementKey2020"
)

var _ did.VerificationMethodKeyAgreement = &KeyAgreementKey2020{}

type KeyAgreementKey2020 struct {
	id         string
	pubkey     PublicKey
	controller string
}

func NewKeyAgreementKey2020(id string, pubkey PublicKey, controller did.DID) (*KeyAgreementKey2020, error) {
	if pubkey.Curve() != ecdh.X25519() {
		return nil, errors.New("x25519 key curve must be X25519")
	}

	return &KeyAgreementKey2020{
		id:         id,
		pubkey:     pubkey,
		controller: controller.String(),
	}, nil
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
		PublicKeyMultibase: PublicKeyToMultibase(k.pubkey),
	})
}

func (k *KeyAgreementKey2020) UnmarshalJSON(bytes []byte) error {
	aux := struct {
		ID                 string `json:"id"`
		Type               string `json:"type"`
		Controller         string `json:"controller"`
		PublicKeyMultibase string `json:"publicKeyMultibase"`
	}{}
	err := json.Unmarshal(bytes, &aux)
	if err != nil {
		return err
	}
	if aux.Type != k.Type() {
		return errors.New("invalid type")
	}
	k.id = aux.ID
	if len(k.id) == 0 {
		return errors.New("invalid id")
	}
	k.pubkey, err = PublicKeyFromMultibase(aux.PublicKeyMultibase)
	if err != nil {
		return fmt.Errorf("invalid publicKeyMultibase: %w", err)
	}
	k.controller = aux.Controller
	if !did.HasValidSyntax(k.controller) {
		return errors.New("invalid controller")
	}
	return nil
}

func (k KeyAgreementKey2020) ID() string {
	return k.id
}

func (k KeyAgreementKey2020) Type() string {
	return Type
}

func (k KeyAgreementKey2020) Controller() string {
	return k.controller
}

func (k KeyAgreementKey2020) JsonLdContext() string {
	return JsonLdContext
}

// TODO: make it part of did.VerificationMethodKeyAgreement in some way
func (k KeyAgreementKey2020) KeyAgreement(priv PrivateKey) ([]byte, error) {
	return priv.ECDH(k.pubkey)
}
