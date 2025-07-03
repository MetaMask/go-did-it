package x25519vm

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mr-tron/base58"

	"github.com/INFURA/go-did"
	"github.com/INFURA/go-did/crypto"
	"github.com/INFURA/go-did/crypto/x25519"
)

// Specification: https://github.com/digitalbazaar/x25519-key-agreement-key-2019

const (
	JsonLdContext2019 = "https://w3id.org/security/suites/x25519-2019/v1"
	Type2019          = "X25519KeyAgreementKey2019"
)

var _ did.VerificationMethodKeyAgreement = &KeyAgreementKey2019{}

type KeyAgreementKey2019 struct {
	id         string
	pubkey     *x25519.PublicKey
	controller string
}

func NewKeyAgreementKey2019(id string, pubkey *x25519.PublicKey, controller did.DID) *KeyAgreementKey2019 {
	return &KeyAgreementKey2019{
		id:         id,
		pubkey:     pubkey,
		controller: controller.String(),
	}
}

func (k KeyAgreementKey2019) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID              string `json:"id"`
		Type            string `json:"type"`
		Controller      string `json:"controller"`
		PublicKeyBase58 string `json:"publicKeyBase58"`
	}{
		ID:              k.ID(),
		Type:            k.Type(),
		Controller:      k.Controller(),
		PublicKeyBase58: base58.Encode(k.pubkey.ToBytes()),
	})
}

func (k *KeyAgreementKey2019) UnmarshalJSON(bytes []byte) error {
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
	if aux.Type != k.Type() {
		return errors.New("invalid type")
	}
	k.id = aux.ID
	if len(k.id) == 0 {
		return errors.New("invalid id")
	}
	pubBytes, err := base58.Decode(aux.PublicKeyBase58)
	if err != nil {
		return fmt.Errorf("invalid publicKeyBase58: %w", err)
	}
	k.pubkey, err = x25519.PublicKeyFromBytes(pubBytes)
	if err != nil {
		return fmt.Errorf("invalid publicKeyBase58: %w", err)
	}
	k.controller = aux.Controller
	if !did.HasValidDIDSyntax(k.controller) {
		return errors.New("invalid controller")
	}
	return nil
}

func (k KeyAgreementKey2019) ID() string {
	return k.id
}

func (k KeyAgreementKey2019) Type() string {
	return Type2019
}

func (k KeyAgreementKey2019) Controller() string {
	return k.controller
}

func (k KeyAgreementKey2019) JsonLdContext() string {
	return JsonLdContext2019
}

func (k KeyAgreementKey2019) PrivateKeyIsCompatible(local crypto.PrivateKeyKeyExchange) bool {
	return local.PublicKeyIsCompatible(k.pubkey)
}

func (k KeyAgreementKey2019) KeyExchange(local crypto.PrivateKeyKeyExchange) ([]byte, error) {
	return local.KeyExchange(k.pubkey)
}
