package didplc

import (
	"encoding/json"
	"net/url"

	"github.com/MetaMask/go-did-it"
)

var _ did.Document = &document{}

type document struct {
	id          string
	alsoKnownAs []*url.URL
	signatures  []did.VerificationMethodSignature
	services    did.Services
}

func (d document) MarshalJSON() ([]byte, error) {
	akas := make([]string, len(d.alsoKnownAs))
	for i, aka := range d.alsoKnownAs {
		akas[i] = aka.String()
	}

	return json.Marshal(struct {
		Context            []string                          `json:"@context"`
		ID                 string                            `json:"id"`
		AlsoKnownAs        []string                          `json:"alsoKnownAs,omitempty"`
		Controller         string                            `json:"controller,omitempty"`
		VerificationMethod []did.VerificationMethodSignature `json:"verificationMethod,omitempty"`
		Services           did.Services                      `json:"service,omitempty"`
	}{
		Context:            d.Context(),
		ID:                 d.id,
		AlsoKnownAs:        akas,
		VerificationMethod: d.signatures,
		Services:           d.services,
	})
}

func (d document) Context() []string {
	res := make([]string, 0, 1+len(d.signatures))
	res = append(res, did.JsonLdContext)
loop:
	for _, method := range d.signatures {
		for _, item := range res {
			if method.JsonLdContext() == item {
				continue loop
			}
		}
		res = append(res, method.JsonLdContext())
	}
	return res
}

func (d document) ID() string {
	return d.id
}

func (d document) Controllers() []string {
	return nil
}

func (d document) AlsoKnownAs() []*url.URL {
	return d.alsoKnownAs
}

func (d document) VerificationMethods() map[string]did.VerificationMethod {
	res := make(map[string]did.VerificationMethod)
	for _, signature := range d.signatures {
		res[signature.ID()] = signature
	}
	return res
}

func (d document) Authentication() []did.VerificationMethodSignature {
	return d.signatures
}

func (d document) Assertion() []did.VerificationMethodSignature {
	return d.signatures
}

func (d document) KeyAgreement() []did.VerificationMethodKeyAgreement {
	return nil
}

func (d document) CapabilityInvocation() []did.VerificationMethodSignature {
	return d.signatures
}

func (d document) CapabilityDelegation() []did.VerificationMethodSignature {
	return d.signatures
}

func (d document) Services() did.Services {
	return d.services
}
