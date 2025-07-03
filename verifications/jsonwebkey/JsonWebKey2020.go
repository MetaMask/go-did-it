package jsonwebkey

import (
	"encoding/json"
	"errors"

	"github.com/INFURA/go-did"
	"github.com/INFURA/go-did/crypto"
	"github.com/INFURA/go-did/crypto/jwk"
)

// Specification:
// - https://www.w3.org/TR/vc-jws-2020/
// - https://w3c-ccg.github.io/lds-jws2020/

const (
	JsonLdContext = "https://w3id.org/security/suites/jws-2020/v1"
	Type          = "JsonWebKey2020"
)

var _ did.VerificationMethodSignature = &JsonWebKey2020{}
var _ did.VerificationMethodKeyAgreement = &JsonWebKey2020{}

type JsonWebKey2020 struct {
	id         string
	pubkey     crypto.PublicKey
	controller string
}

func NewJsonWebKey2020(id string, pubkey crypto.PublicKey, controller did.DID) *JsonWebKey2020 {
	return &JsonWebKey2020{
		id:         id,
		pubkey:     pubkey,
		controller: controller.String(),
	}
}

func (j JsonWebKey2020) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID           string        `json:"id"`
		Type         string        `json:"type"`
		Controller   string        `json:"controller"`
		PublicKeyJWK jwk.PublicJwk `json:"publicKeyJwk"`
	}{
		ID:           j.ID(),
		Type:         j.Type(),
		Controller:   j.Controller(),
		PublicKeyJWK: jwk.PublicJwk{Pubkey: j.pubkey},
	})
}

func (j *JsonWebKey2020) UnmarshalJSON(bytes []byte) error {
	aux := struct {
		ID           string        `json:"id"`
		Type         string        `json:"type"`
		Controller   string        `json:"controller"`
		PublicKeyJWK jwk.PublicJwk `json:"publicKeyJwk"`
	}{}
	err := json.Unmarshal(bytes, &aux)
	if err != nil {
		return err
	}
	if aux.Type != j.Type() {
		return errors.New("invalid type")
	}
	j.id = aux.ID
	if len(j.id) == 0 {
		return errors.New("invalid id")
	}
	j.controller = aux.Controller
	if !did.HasValidDIDSyntax(j.controller) {
		return errors.New("invalid controller")
	}

	j.pubkey = aux.PublicKeyJWK.Pubkey

	return nil
}

func (j JsonWebKey2020) ID() string {
	return j.id
}

func (j JsonWebKey2020) Type() string {
	return Type
}

func (j JsonWebKey2020) Controller() string {
	return j.controller
}

func (j JsonWebKey2020) JsonLdContext() string {
	return JsonLdContext
}

func (j JsonWebKey2020) Verify(data []byte, sig []byte) (bool, error) {
	if pub, ok := j.pubkey.(crypto.PublicKeySigning); ok {
		return pub.VerifyBytes(data, sig), nil
	}
	return false, errors.New("not a signing public key")
}

func (j JsonWebKey2020) PrivateKeyIsCompatible(local crypto.PrivateKeyKeyExchange) bool {
	return local.PublicKeyIsCompatible(j.pubkey)
}

func (j JsonWebKey2020) KeyExchange(local crypto.PrivateKeyKeyExchange) ([]byte, error) {
	return local.KeyExchange(j.pubkey)
}
