package x25519vm

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/INFURA/go-did"
	"github.com/INFURA/go-did/crypto"
	"github.com/INFURA/go-did/crypto/x25519"
)

// Specification: https://w3c-ccg.github.io/did-method-key/#ed25519-x25519

const (
	JsonLdContext2020 = "https://w3id.org/security/suites/x25519-2020/v1"
	Type2020          = "X25519KeyAgreementKey2020"
)

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
	k.pubkey, err = x25519.PublicKeyFromPublicKeyMultibase(aux.PublicKeyMultibase)
	if err != nil {
		return fmt.Errorf("invalid publicKeyMultibase: %w", err)
	}
	k.controller = aux.Controller
	if !did.HasValidDIDSyntax(k.controller) {
		return errors.New("invalid controller")
	}
	return nil
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
