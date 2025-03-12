package Ed25519

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"

	"github.com/INFURA/go-did"
)

var _ did.VerificationMethod = &VerificationKey2020{}

type VerificationKey2020 struct {
	id         string
	pubkey     ed25519.PublicKey
	controller did.DID
}

func NewVerificationKey2020(id string, pubkey []byte, controller did.DID) (*VerificationKey2020, error) {
	if len(pubkey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid ed25519 public key size")
	}

	return &VerificationKey2020{
		id:         id,
		pubkey:     pubkey,
		controller: controller,
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
		Controller:         v.Controller().String(),
		PublicKeyMultibase: v,
	})

	/*

		{
		    "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		    "type": "Ed25519VerificationKey2020",
		    "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		    "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
		  }

	*/
}

func (v VerificationKey2020) UnmarshalJSON(bytes []byte) error {
	// TODO implement me
	panic("implement me")
}

func (v VerificationKey2020) ID() string {
	return v.id
}

func (v VerificationKey2020) Type() string {
	return "Ed25519VerificationKey2020"
}

func (v VerificationKey2020) Controller() did.DID {
	return v.controller
}

func (v VerificationKey2020) Verify(data []byte, sig []byte) bool {
	return ed25519.Verify(v.pubkey, data, sig)
}
