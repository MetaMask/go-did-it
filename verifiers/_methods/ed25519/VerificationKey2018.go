package ed25519vm

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mr-tron/base58"

	"github.com/MetaMask/go-did-it"
	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/ed25519"
	methods "github.com/MetaMask/go-did-it/verifiers/_methods"
)

// Specification: https://w3c-ccg.github.io/lds-ed25519-2018/

const (
	JsonLdContext2018 = "https://w3id.org/security/suites/ed25519-2018/v1"
	Type2018          = "Ed25519VerificationKey2018"
)

func init() {
	methods.Register(Type2018, func(data []byte, kp *crypto.KeyPolicy) (did.VerificationMethod, error) {
		return NewVerificationKey2018FromJSON(data, kp)
	})
}

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

// NewVerificationKey2018FromJSON decodes an Ed25519VerificationKey2018 verification method from
// JSON, using kp to decode and accept the publicKeyBase58 field. If kp is nil,
// crypto.DefaultKeyPolicy is used.
func NewVerificationKey2018FromJSON(data []byte, kp *crypto.KeyPolicy) (*VerificationKey2018, error) {
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
	if aux.Type != Type2018 {
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
	pub, err := kp.PublicKeyFromBytes(ed25519.MultibaseCode, pubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid publicKeyBase58: %w", err)
	}
	pubkey, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("publicKeyBase58 is not an Ed25519 key")
	}
	return &VerificationKey2018{id: aux.ID, pubkey: pubkey, controller: aux.Controller}, nil
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

// UnmarshalJSON always fails: decoding needs a crypto.KeyPolicy. See methods.ErrDirectUnmarshal.
func (v VerificationKey2018) UnmarshalJSON([]byte) error {
	return fmt.Errorf("%w: use ed25519vm.NewVerificationKey2018FromJSON", methods.ErrDirectUnmarshal)
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
