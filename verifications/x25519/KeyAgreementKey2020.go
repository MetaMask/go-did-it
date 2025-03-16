package x25519

import (
	"encoding/json"
	"errors"
	"fmt"

	mbase "github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"

	"github.com/INFURA/go-did"
)

// Specification: https://w3c-ccg.github.io/did-method-key/#ed25519-x25519

const (
	MultibaseCode = uint64(0xec)
	JsonLdContext = "https://w3id.org/security/suites/x25519-2020/v1"
)

var _ did.VerificationMethodKeyAgreement = &KeyAgreementKey2020{}

type KeyAgreementKey2020 struct {
	id         string
	pubkey     PublicKey
	controller string
}

func NewKeyAgreementKey2020(id string, pubkey PublicKey, controller did.DID) (*KeyAgreementKey2020, error) {
	if len(pubkey) != PublicKeySize {
		return nil, errors.New("invalid x25519 public key size")
	}

	return &KeyAgreementKey2020{
		id:         id,
		pubkey:     pubkey,
		controller: controller.String(),
	}, nil
}

func (k KeyAgreementKey2020) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID                 string `json:"id"`
		Type               string `json:"type"`
		Controller         string `json:"controller"`
		PublicKeyMultibase string `json:"publicKeyMultibase"`
	}{
		ID:                 k.ID(),
		Type:               k.Type(),
		Controller:         k.Controller(),
		PublicKeyMultibase: PublicKeyToMultibase(k.pubkey),
	})
}

func (k *KeyAgreementKey2020) UnmarshalJSON(bytes []byte) error {
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
	if aux.Type != k.Type() {
		return errors.New("invalid type")
	}
	k.id = aux.ID
	if len(k.id) == 0 {
		return errors.New("invalid id")
	}
	k.pubkey, err = MultibaseToPublicKey(aux.PublicKeyMultibase)
	if err != nil {
		return fmt.Errorf("invalid publicKeyMultibase: %w", err)
	}
	k.controller = aux.Controller
	if !did.HasValidSyntax(k.controller) {
		return errors.New("invalid controller")
	}
	return nil
}

func (k KeyAgreementKey2020) ID() string {
	return k.id
}

func (k KeyAgreementKey2020) Type() string {
	return "X25519KeyAgreementKey2020"
}

func (k KeyAgreementKey2020) Controller() string {
	return k.controller
}

func (k KeyAgreementKey2020) JsonLdContext() string {
	return JsonLdContext
}

// PublicKeyToMultibase encodes the public key in a suitable way for publicKeyMultibase
func PublicKeyToMultibase(pub PublicKey) string {
	// can only fail with an invalid encoding, but it's hardcoded
	bytes, _ := mbase.Encode(mbase.Base58BTC, append(varint.ToUvarint(MultibaseCode), pub...))
	return bytes
}

// MultibaseToPublicKey decodes the public key from its publicKeyMultibase form
func MultibaseToPublicKey(multibase string) (PublicKey, error) {
	baseCodec, bytes, err := mbase.Decode(multibase)
	if err != nil {
		return nil, err
	}
	// the specification enforces that encoding
	if baseCodec != mbase.Base58BTC {
		return nil, fmt.Errorf("not Base58BTC encoded")
	}
	code, read, err := varint.FromUvarint(bytes)
	if err != nil {
		return nil, err
	}
	if code != MultibaseCode {
		return nil, fmt.Errorf("invalid code")
	}
	if read != 2 {
		return nil, fmt.Errorf("unexpected multibase")
	}
	if len(bytes)-read != PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key size")
	}
	return bytes[read:], nil
}
