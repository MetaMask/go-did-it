package methods

import (
	"encoding/json"
	"fmt"

	"github.com/MetaMask/go-did-it"
	"github.com/MetaMask/go-did-it/verifiers/_methods/ed25519"
	"github.com/MetaMask/go-did-it/verifiers/_methods/jsonwebkey"
	"github.com/MetaMask/go-did-it/verifiers/_methods/multikey"
	p256vm "github.com/MetaMask/go-did-it/verifiers/_methods/p256"
	secp256k1vm "github.com/MetaMask/go-did-it/verifiers/_methods/secp256k1"
	"github.com/MetaMask/go-did-it/verifiers/_methods/x25519"
)

func UnmarshalJSON(data []byte) (did.VerificationMethod, error) {
	var aux struct {
		Type string
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return nil, err
	}

	var res did.VerificationMethod
	switch aux.Type {
	case ed25519vm.Type2018:
		res = &ed25519vm.VerificationKey2018{}
	case ed25519vm.Type2020:
		res = &ed25519vm.VerificationKey2020{}
	case multikey.Type:
		res = &multikey.MultiKey{}
	case p256vm.Type2021:
		res = &p256vm.Key2021{}
	case secp256k1vm.Type2019:
		res = &secp256k1vm.VerificationKey2019{}
	case x25519vm.Type2019:
		res = &x25519vm.KeyAgreementKey2019{}
	case x25519vm.Type2020:
		res = &x25519vm.KeyAgreementKey2020{}
	case jsonwebkey.Type:
		res = &jsonwebkey.JsonWebKey2020{}
	default:
		return nil, fmt.Errorf("unknown verification type: %s", aux.Type)
	}

	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}
	return res, nil
}
