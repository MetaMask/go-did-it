package ed25519vm

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mr-tron/base58"

	"github.com/MetaMask/go-did-it"
	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/ed25519"
)

// Specification: https://w3c-ccg.github.io/lds-ed25519-2018/

const (
	JsonLdContext2018 = "https://w3id.org/security/suites/ed25519-2018/v1"
	Type2018          = "Ed25519VerificationKey2018"
)

var _ did.VerificationMethodSignature = &VerificationKey2018{}

type VerificationKey2018 struct {
	id         string
	pubkey     ed25519.PublicKey
	controller string
}

func NewVerificationKey2018(id string, pubkey ed25519.PublicKey, controller did.DID) *VerificationKey2018 {
	return &VerificationKey2018{
		id:         id,
		pubkey:     pubkey,
		controller: controller.String(),
	}
}

func (v VerificationKey2018) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID              string `json:"id"`
		Type            string `json:"type"`
		Controller      string `json:"controller"`
		PublicKeyBase58 string `json:"publicKeyBase58"`
	}{
		ID:              v.ID(),
		Type:            v.Type(),
		Controller:      v.Controller(),
		PublicKeyBase58: base58.Encode(v.pubkey.ToBytes()),
	})
}

func (v *VerificationKey2018) UnmarshalJSON(bytes []byte) error {
	aux := struct {
		ID              string `json:"id"`
		Type            string `json:"type"`
		Controller      string `json:"controller"`
		PublicKeyBase58 string `json:"publicKeyBase58"`
	}{}
	err := json.Unmarshal(bytes, &aux)
	if err != nil {
		return err
	}
	if aux.Type != v.Type() {
		return errors.New("invalid type")
	}
	v.id = aux.ID
	if len(v.id) == 0 {
		return errors.New("invalid id")
	}
	pubBytes, err := base58.Decode(aux.PublicKeyBase58)
	if err != nil {
		return fmt.Errorf("invalid publicKeyBase58: %w", err)
	}
	v.pubkey, err = ed25519.PublicKeyFromBytes(pubBytes)
	if err != nil {
		return fmt.Errorf("invalid publicKeyBase58: %w", err)
	}
	v.controller = aux.Controller
	if !did.HasValidDIDSyntax(v.controller) {
		return errors.New("invalid controller")
	}
	return nil
}

func (v VerificationKey2018) ID() string {
	return v.id
}

func (v VerificationKey2018) Type() string {
	return Type2018
}

func (v VerificationKey2018) Controller() string {
	return v.controller
}

func (v VerificationKey2018) JsonLdContext() string {
	return JsonLdContext2018
}

func (v VerificationKey2018) VerifyBytes(data []byte, sig []byte, opts ...crypto.SigningOption) (bool, error) {
	return v.pubkey.VerifyBytes(data, sig, opts...), nil
}

func (v VerificationKey2018) VerifyASN1(data []byte, sig []byte, opts ...crypto.SigningOption) (bool, error) {
	return v.pubkey.VerifyASN1(data, sig, opts...), nil
}
