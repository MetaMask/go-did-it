package p256vm

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mr-tron/base58"

	"github.com/MetaMask/go-did-it"
	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/p256"
	methods "github.com/MetaMask/go-did-it/verifiers/methods"
)

// Specification: missing

const (
	JsonLdContext2021 = "https://w3id.org/security/suites/multikey-2021/v1"
	Type2021          = "P256Key2021"
)

func init() {
	methods.Register(Type2021, func(data []byte, kp *crypto.KeyPolicy) (did.VerificationMethod, error) {
		return NewKey2021FromJSON(data, kp)
	})
}

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

// NewKey2021FromJSON decodes a P256Key2021 verification method from JSON, using kp to decode and
// accept the publicKeyBase58 field. If kp is nil, crypto.DefaultKeyPolicy is used.
func NewKey2021FromJSON(data []byte, kp *crypto.KeyPolicy) (*Key2021, error) {
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
	if aux.Type != Type2021 {
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
	pub, err := kp.PublicKeyFromBytes(p256.MultibaseCode, pubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid publicKeyBase58: %w", err)
	}
	pubkey, ok := pub.(*p256.PublicKey)
	if !ok {
		return nil, errors.New("publicKeyBase58 is not a P-256 key")
	}
	return &Key2021{id: aux.ID, pubkey: pubkey, controller: aux.Controller}, nil
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

// UnmarshalJSON always fails: decoding needs a crypto.KeyPolicy. See methods.ErrDirectUnmarshal.
func (m Key2021) UnmarshalJSON([]byte) error {
	return fmt.Errorf("%w: use p256vm.NewKey2021FromJSON", methods.ErrDirectUnmarshal)
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
