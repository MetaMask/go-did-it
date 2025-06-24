package multikey

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/INFURA/go-did"
	"github.com/INFURA/go-did/crypto"
	helpers "github.com/INFURA/go-did/crypto/_helpers"
	"github.com/INFURA/go-did/crypto/ed25519"
	"github.com/INFURA/go-did/crypto/p256"
	"github.com/INFURA/go-did/crypto/x25519"
)

// Specification: https://www.w3.org/TR/cid-1.0/#Multikey

const (
	JsonLdContext = "https://www.w3.org/ns/cid/v1"
	Type          = "Multikey"
)

var _ did.VerificationMethodSignature = &MultiKey{}
var _ did.VerificationMethodKeyAgreement = &MultiKey{}

type MultiKey struct {
	id         string
	pubkey     crypto.PublicKey
	controller string
}

func NewMultiKey(id string, pubkey crypto.PublicKey, controller did.DID) *MultiKey {
	return &MultiKey{
		id:         id,
		pubkey:     pubkey,
		controller: controller.String(),
	}
}

func (m MultiKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID                 string `json:"id"`
		Type               string `json:"type"`
		Controller         string `json:"controller"`
		PublicKeyMultibase string `json:"publicKeyMultibase"`
	}{
		ID:                 m.ID(),
		Type:               m.Type(),
		Controller:         m.Controller(),
		PublicKeyMultibase: m.pubkey.ToPublicKeyMultibase(),
	})
}

func (m *MultiKey) UnmarshalJSON(bytes []byte) error {
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
	if aux.Type != m.Type() {
		return errors.New("invalid type")
	}
	m.id = aux.ID
	if len(m.id) == 0 {
		return errors.New("invalid id")
	}

	code, pubBytes, err := helpers.PublicKeyMultibaseDecode(aux.PublicKeyMultibase)
	if err != nil {
		return fmt.Errorf("invalid publicKeyMultibase: %w", err)
	}
	decoder, ok := map[uint64]func(b []byte) (crypto.PublicKey, error){
		ed25519.MultibaseCode: func(b []byte) (crypto.PublicKey, error) { return ed25519.PublicKeyFromBytes(b) },
		p256.MultibaseCode:    func(b []byte) (crypto.PublicKey, error) { return p256.PublicKeyFromBytes(b) },
		x25519.MultibaseCode:  func(b []byte) (crypto.PublicKey, error) { return x25519.PublicKeyFromBytes(b) },
	}[code]
	if !ok {
		return fmt.Errorf("unsupported publicKeyMultibase code: %d", code)
	}
	m.pubkey, err = decoder(pubBytes)
	if err != nil {
		return fmt.Errorf("invalid publicKeyMultibase: %w", err)
	}

	m.controller = aux.Controller
	if !did.HasValidDIDSyntax(m.controller) {
		return errors.New("invalid controller")
	}
	return nil
}

func (m MultiKey) ID() string {
	return m.id
}

func (m MultiKey) Type() string {
	return Type
}

func (m MultiKey) Controller() string {
	return m.controller
}

func (m MultiKey) JsonLdContext() string {
	return JsonLdContext
}

func (m MultiKey) Verify(data []byte, sig []byte) (bool, error) {
	if pub, ok := m.pubkey.(crypto.SigningPublicKey); ok {
		return pub.VerifyBytes(data, sig), nil
	}
	return false, errors.New("not a signing public key")
}

func (m MultiKey) PrivateKeyIsCompatible(local crypto.KeyExchangePrivateKey) bool {
	return local.PublicKeyIsCompatible(m.pubkey)
}

func (m MultiKey) KeyExchange(local crypto.KeyExchangePrivateKey) ([]byte, error) {
	return local.KeyExchange(m.pubkey)
}
