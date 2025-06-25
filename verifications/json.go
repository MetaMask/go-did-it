package verifications

import (
	"encoding/json"
	"fmt"

	"github.com/INFURA/go-did"
	"github.com/INFURA/go-did/verifications/ed25519"
	"github.com/INFURA/go-did/verifications/multikey"
	"github.com/INFURA/go-did/verifications/x25519"
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
	case ed25519vm.Type:
		res = &ed25519vm.VerificationKey2020{}
	case multikey.Type:
		res = &multikey.MultiKey{}
	case x25519vm.Type:
		res = &x25519vm.KeyAgreementKey2020{}
	default:
		return nil, fmt.Errorf("unknown verification type: %s", aux.Type)
	}

	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}
	return res, nil
}
