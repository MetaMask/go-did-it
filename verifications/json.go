package verifications

import (
	"encoding/json"
	"fmt"

	"github.com/INFURA/go-did"
	"github.com/INFURA/go-did/verifications/ed25519"
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
	case ed25519.Type:
		res = &ed25519.VerificationKey2020{}
	case x25519.Type:
		res = &x25519.KeyAgreementKey2020{}
	default:
		return nil, fmt.Errorf("unknown verification type: %s", aux.Type)
	}

	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}
	return res, nil
}
