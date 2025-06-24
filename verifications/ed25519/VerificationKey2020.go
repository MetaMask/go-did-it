package ed25519vm

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/INFURA/go-did"
	"github.com/INFURA/go-did/crypto/ed25519"
)

// Specification: https://w3c.github.io/cg-reports/credentials/CG-FINAL-di-eddsa-2020-20220724/

const (
	JsonLdContext = "https://w3id.org/security/suites/ed25519-2020/v1"
	Type          = "Ed25519VerificationKey2020"
)

var _ did.VerificationMethodSignature = &VerificationKey2020{}

type VerificationKey2020 struct {
	id         string
	pubkey     ed25519.PublicKey
	controller string
}

func NewVerificationKey2020(id string, pubkey ed25519.PublicKey, controller did.DID) (*VerificationKey2020, error) {
	return &VerificationKey2020{
		id:         id,
		pubkey:     pubkey,
		controller: controller.String(),
	}, nil
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

func (v *VerificationKey2020) UnmarshalJSON(bytes []byte) error {
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
	if aux.Type != v.Type() {
		return errors.New("invalid type")
	}
	v.id = aux.ID
	if len(v.id) == 0 {
		return errors.New("invalid id")
	}
	v.pubkey, err = ed25519.PublicKeyFromPublicKeyMultibase(aux.PublicKeyMultibase)
	if err != nil {
		return fmt.Errorf("invalid publicKeyMultibase: %w", err)
	}
	v.controller = aux.Controller
	if !did.HasValidDIDSyntax(v.controller) {
		return errors.New("invalid controller")
	}
	return nil
}

func (v VerificationKey2020) ID() string {
	return v.id
}

func (v VerificationKey2020) Type() string {
	return Type
}

func (v VerificationKey2020) Controller() string {
	return v.controller
}

func (v VerificationKey2020) JsonLdContext() string {
	return JsonLdContext
}

func (v VerificationKey2020) Verify(data []byte, sig []byte) bool {
	return v.pubkey.VerifyBytes(data, sig)
}
