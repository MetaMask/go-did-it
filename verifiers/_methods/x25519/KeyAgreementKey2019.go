package x25519vm

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mr-tron/base58"

	"github.com/MetaMask/go-did-it"
	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/x25519"
	methods "github.com/MetaMask/go-did-it/verifiers/_methods"
)

// Specification: https://github.com/digitalbazaar/x25519-key-agreement-key-2019

const (
	JsonLdContext2019 = "https://w3id.org/security/suites/x25519-2019/v1"
	Type2019          = "X25519KeyAgreementKey2019"
)

func init() {
	methods.Register(Type2019, func(data []byte, kp *crypto.KeyPolicy) (did.VerificationMethod, error) {
		return NewKeyAgreementKey2019FromJSON(data, kp)
	})
}

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

// NewKeyAgreementKey2019FromJSON decodes an X25519KeyAgreementKey2019 verification method from
// JSON, using kp to decode and accept the publicKeyBase58 field. If kp is nil,
// crypto.DefaultKeyPolicy is used.
func NewKeyAgreementKey2019FromJSON(data []byte, kp *crypto.KeyPolicy) (*KeyAgreementKey2019, error) {
	if kp == nil {
		kp = crypto.DefaultKeyPolicy
	}
	aux := struct {
		ID              string `json:"id"`
		Type            string `json:"type"`
		Controller      string `json:"controller"`
		PublicKeyBase58 string `json:"publicKeyBase58"`
	}{}
	if err := json.Unmarshal(data, &aux); err != nil {
		return nil, err
	}
	if aux.Type != Type2019 {
		return nil, errors.New("invalid type")
	}
	if len(aux.ID) == 0 {
		return nil, errors.New("invalid id")
	}
	if !did.HasValidDIDSyntax(aux.Controller) {
		return nil, errors.New("invalid controller")
	}
	pubBytes, err := base58.Decode(aux.PublicKeyBase58)
	if err != nil {
		return nil, fmt.Errorf("invalid publicKeyBase58: %w", err)
	}
	pub, err := kp.PublicKeyFromBytes(x25519.MultibaseCode, pubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid publicKeyBase58: %w", err)
	}
	pubkey, ok := pub.(*x25519.PublicKey)
	if !ok {
		return nil, errors.New("publicKeyBase58 is not an X25519 key")
	}
	return &KeyAgreementKey2019{id: aux.ID, pubkey: pubkey, controller: aux.Controller}, nil
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

// UnmarshalJSON always fails: decoding needs a crypto.KeyPolicy. See methods.ErrDirectUnmarshal.
func (k KeyAgreementKey2019) UnmarshalJSON([]byte) error {
	return fmt.Errorf("%w: use x25519vm.NewKeyAgreementKey2019FromJSON", methods.ErrDirectUnmarshal)
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
