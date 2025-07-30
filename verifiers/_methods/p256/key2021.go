package p256vm

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mr-tron/base58"

	"github.com/MetaMask/go-did-it"
	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/p256"
)

// Specification: missing

const (
	JsonLdContext2021 = "https://w3id.org/security/suites/multikey-2021/v1"
	Type2021          = "P256Key2021"
)

var _ did.VerificationMethodSignature = &Key2021{}
var _ did.VerificationMethodKeyAgreement = &Key2021{}

type Key2021 struct {
	id         string
	pubkey     *p256.PublicKey
	controller string
}

func NewKey2021(id string, pubkey *p256.PublicKey, controller did.DID) *Key2021 {
	return &Key2021{
		id:         id,
		pubkey:     pubkey,
		controller: controller.String(),
	}
}

func (m Key2021) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID              string `json:"id"`
		Type            string `json:"type"`
		Controller      string `json:"controller"`
		PublicKeyBase58 string `json:"publicKeyBase58"`
	}{
		ID:              m.ID(),
		Type:            m.Type(),
		Controller:      m.Controller(),
		PublicKeyBase58: base58.Encode(m.pubkey.ToBytes()),
	})
}

func (m *Key2021) UnmarshalJSON(bytes []byte) error {
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
	if aux.Type != m.Type() {
		return errors.New("invalid type")
	}
	m.id = aux.ID
	if len(m.id) == 0 {
		return errors.New("invalid id")
	}
	m.controller = aux.Controller
	if !did.HasValidDIDSyntax(m.controller) {
		return errors.New("invalid controller")
	}

	pubBytes, err := base58.Decode(aux.PublicKeyBase58)
	if err != nil {
		return fmt.Errorf("invalid publicKeyBase58: %w", err)
	}
	m.pubkey, err = p256.PublicKeyFromBytes(pubBytes)
	if err != nil {
		return fmt.Errorf("invalid publicKeyBase58: %w", err)
	}

	return nil
}

func (m Key2021) ID() string {
	return m.id
}

func (m Key2021) Type() string {
	return Type2021
}

func (m Key2021) Controller() string {
	return m.controller
}

func (m Key2021) JsonLdContext() string {
	return JsonLdContext2021
}

func (m Key2021) VerifyBytes(data []byte, sig []byte, opts ...crypto.SigningOption) (bool, error) {
	return m.pubkey.VerifyBytes(data, sig, opts...), nil
}

func (m Key2021) VerifyASN1(data []byte, sig []byte, opts ...crypto.SigningOption) (bool, error) {
	return m.pubkey.VerifyASN1(data, sig, opts...), nil
}

func (m Key2021) PrivateKeyIsCompatible(local crypto.PrivateKeyKeyExchange) bool {
	return local.PublicKeyIsCompatible(m.pubkey)
}

func (m Key2021) KeyExchange(local crypto.PrivateKeyKeyExchange) ([]byte, error) {
	return local.KeyExchange(m.pubkey)
}
