package secp256k1vm

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mr-tron/base58"

	"github.com/ucan-wg/go-did-it"
	"github.com/ucan-wg/go-did-it/crypto"
	"github.com/ucan-wg/go-did-it/crypto/secp256k1"
)

// Specification: https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/

const (
	JsonLdContext = "https://w3id.org/security/suites/secp256k1-2019/v1"
	Type2019      = "EcdsaSecp256k1VerificationKey2019"
)

var _ did.VerificationMethodSignature = &VerificationKey2019{}
var _ did.VerificationMethodKeyAgreement = &VerificationKey2019{}

type VerificationKey2019 struct {
	id         string
	pubkey     *secp256k1.PublicKey
	controller string
}

func NewVerificationKey2019(id string, pubkey *secp256k1.PublicKey, controller did.DID) *VerificationKey2019 {
	return &VerificationKey2019{
		id:         id,
		pubkey:     pubkey,
		controller: controller.String(),
	}
}

func (vm VerificationKey2019) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID              string `json:"id"`
		Type            string `json:"type"`
		Controller      string `json:"controller"`
		PublicKeyBase58 string `json:"publicKeyBase58"`
	}{
		ID:              vm.ID(),
		Type:            vm.Type(),
		Controller:      vm.Controller(),
		PublicKeyBase58: base58.Encode(vm.pubkey.ToBytes()),
	})
}

func (vm *VerificationKey2019) UnmarshalJSON(bytes []byte) error {
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
	if aux.Type != vm.Type() {
		return errors.New("invalid type")
	}
	vm.id = aux.ID
	if len(vm.id) == 0 {
		return errors.New("invalid id")
	}
	vm.controller = aux.Controller
	if !did.HasValidDIDSyntax(vm.controller) {
		return errors.New("invalid controller")
	}

	pubBytes, err := base58.Decode(aux.PublicKeyBase58)
	if err != nil {
		return fmt.Errorf("invalid publicKeyBase58: %w", err)
	}
	vm.pubkey, err = secp256k1.PublicKeyFromBytes(pubBytes)
	if err != nil {
		return fmt.Errorf("invalid publicKeyBase58: %w", err)
	}

	return nil
}

func (vm VerificationKey2019) ID() string {
	return vm.id
}

func (vm VerificationKey2019) Type() string {
	return Type2019
}

func (vm VerificationKey2019) Controller() string {
	return vm.controller
}

func (vm VerificationKey2019) JsonLdContext() string {
	return JsonLdContext
}

func (vm VerificationKey2019) Verify(data []byte, sig []byte) (bool, error) {
	return vm.pubkey.VerifyBytes(data, sig), nil
}

func (vm VerificationKey2019) PrivateKeyIsCompatible(local crypto.PrivateKeyKeyExchange) bool {
	return local.PublicKeyIsCompatible(vm.pubkey)
}

func (vm VerificationKey2019) KeyExchange(local crypto.PrivateKeyKeyExchange) ([]byte, error) {
	return local.KeyExchange(vm.pubkey)
}
