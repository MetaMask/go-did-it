package multikey

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/MetaMask/go-did-it"
	"github.com/MetaMask/go-did-it/crypto"
	allkeys "github.com/MetaMask/go-did-it/crypto/_allkeys"
)

// Specification: https://www.w3.org/TR/cid-1.0/#Multikey

const (
	// This is apparently the right context despite the spec above saying otherwise.
	JsonLdContext = "https://w3id.org/security/multikey/v1"
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
	m.controller = aux.Controller
	if !did.HasValidDIDSyntax(m.controller) {
		return errors.New("invalid controller")
	}

	m.pubkey, err = allkeys.PublicKeyFromPublicKeyMultibase(aux.PublicKeyMultibase)
	if err != nil {
		return fmt.Errorf("invalid publicKeyMultibase: %w", err)
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
	if pub, ok := m.pubkey.(crypto.PublicKeySigningBytes); ok {
		return pub.VerifyBytes(data, sig), nil
	}
	return false, errors.New("not a signing public key")
}

func (m MultiKey) PrivateKeyIsCompatible(local crypto.PrivateKeyKeyExchange) bool {
	return local.PublicKeyIsCompatible(m.pubkey)
}

func (m MultiKey) KeyExchange(local crypto.PrivateKeyKeyExchange) ([]byte, error) {
	return local.KeyExchange(m.pubkey)
}
