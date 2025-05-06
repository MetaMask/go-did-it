package ed25519

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/INFURA/go-did"
)

// Specification: https://w3c.github.io/cg-reports/credentials/CG-FINAL-di-eddsa-2020-20220724/

const (
	MultibaseCode = uint64(0xed)
	JsonLdContext = "https://w3id.org/security/suites/ed25519-2020/v1"
)

var _ did.VerificationMethodSignature = &VerificationKey2020{}

type VerificationKey2020 struct {
	id         string
	pubkey     PublicKey
	controller string
}

func NewVerificationKey2020(id string, pubkey PublicKey, controller did.DID) (*VerificationKey2020, error) {
	if len(pubkey) != PublicKeySize {
		return nil, errors.New("invalid ed25519 public key size")
	}

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
		PublicKeyMultibase: PublicKeyToMultibase(v.pubkey),
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
	v.pubkey, err = PublicKeyFromMultibase(aux.PublicKeyMultibase)
	if err != nil {
		return fmt.Errorf("invalid publicKeyMultibase: %w", err)
	}
	v.controller = aux.Controller
	if !did.HasValidSyntax(v.controller) {
		return errors.New("invalid controller")
	}
	return nil
}

func (v VerificationKey2020) ID() string {
	return v.id
}

func (v VerificationKey2020) Type() string {
	return "Ed25519VerificationKey2020"
}

func (v VerificationKey2020) Controller() string {
	return v.controller
}

func (v VerificationKey2020) JsonLdContext() string {
	return JsonLdContext
}

func (v VerificationKey2020) Verify(data []byte, sig []byte) bool {
	return ed25519.Verify(v.pubkey, data, sig)
}
