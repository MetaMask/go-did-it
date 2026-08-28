package secp256k1vm

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mr-tron/base58"

	"github.com/MetaMask/go-did-it"
	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/secp256k1"
	methods "github.com/MetaMask/go-did-it/verifiers/methods"
)

// Specification: https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/

const (
	JsonLdContext        = "https://w3id.org/security/suites/secp256k1-2019/v1"
	TypeVerification2019 = "EcdsaSecp256k1VerificationKey2019"
)

func init() {
	methods.Register(TypeVerification2019, func(data []byte, kp *crypto.KeyPolicy) (did.VerificationMethod, error) {
		return NewVerificationKey2019FromJSON(data, kp)
	})
}

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

// NewVerificationKey2019FromJSON decodes an EcdsaSecp256k1VerificationKey2019 verification
// method from JSON, using kp to decode and accept the publicKeyBase58 field. If kp is nil,
// crypto.DefaultKeyPolicy is used.
func NewVerificationKey2019FromJSON(data []byte, kp *crypto.KeyPolicy) (*VerificationKey2019, error) {
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
	if aux.Type != TypeVerification2019 {
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
	pub, err := kp.PublicKeyFromBytes(secp256k1.MultibaseCode, pubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid publicKeyBase58: %w", err)
	}
	pubkey, ok := pub.(*secp256k1.PublicKey)
	if !ok {
		return nil, errors.New("publicKeyBase58 is not a secp256k1 key")
	}
	return &VerificationKey2019{id: aux.ID, pubkey: pubkey, controller: aux.Controller}, nil
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

// UnmarshalJSON always fails: decoding needs a crypto.KeyPolicy. See methods.ErrDirectUnmarshal.
func (vm VerificationKey2019) UnmarshalJSON([]byte) error {
	return fmt.Errorf("%w: use secp256k1vm.NewVerificationKey2019FromJSON", methods.ErrDirectUnmarshal)
}

func (vm VerificationKey2019) ID() string {
	return vm.id
}

func (vm VerificationKey2019) Type() string {
	return TypeVerification2019
}

func (vm VerificationKey2019) Controller() string {
	return vm.controller
}

func (vm VerificationKey2019) JsonLdContext() string {
	return JsonLdContext
}

func (vm VerificationKey2019) VerifyBytes(data []byte, sig []byte, opts ...crypto.SigningOption) (bool, error) {
	return vm.pubkey.VerifyBytes(data, sig, opts...), nil
}

func (vm VerificationKey2019) VerifyASN1(data []byte, sig []byte, opts ...crypto.SigningOption) (bool, error) {
	return vm.pubkey.VerifyASN1(data, sig, opts...), nil
}

func (vm VerificationKey2019) PrivateKeyIsCompatible(local crypto.PrivateKeyKeyExchange) bool {
	return local.PublicKeyIsCompatible(vm.pubkey)
}

func (vm VerificationKey2019) KeyExchange(local crypto.PrivateKeyKeyExchange) ([]byte, error) {
	return local.KeyExchange(vm.pubkey)
}
