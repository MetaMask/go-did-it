package ed25519

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	mbase "github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"

	"github.com/INFURA/go-did"
)

const (
	MultibaseCode = uint64(0xed)
	JsonLdContext = "https://w3id.org/security/suites/ed25519-2020/v1"
)

var _ did.VerificationMethod = &VerificationKey2020{}

type VerificationKey2020 struct {
	id         string
	pubkey     ed25519.PublicKey
	controller string
}

func NewVerificationKey2020(id string, pubkey []byte, controller did.DID) (*VerificationKey2020, error) {
	if len(pubkey) != ed25519.PublicKeySize {
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
		PublicKeyMultibase: encodePubkey(v.pubkey),
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
	v.pubkey, err = decodePubkey(aux.PublicKeyMultibase)
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

// encodePubkey encodes the public key in a suitable way for publicKeyMultibase
func encodePubkey(pubkey ed25519.PublicKey) string {
	// can only fail with an invalid encoding, but it's hardcoded
	bytes, _ := mbase.Encode(mbase.Base58BTC, append(varint.ToUvarint(MultibaseCode), pubkey...))
	return bytes
}

// decodePubkey decodes the public key from its publicKeyMultibase form
func decodePubkey(encoded string) (ed25519.PublicKey, error) {
	baseCodec, bytes, err := mbase.Decode(encoded)
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
	if len(bytes)-read != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key size")
	}
	return bytes[read:], nil
}
