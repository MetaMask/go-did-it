package did_key

import (
	"encoding/json"
	"net/url"

	"github.com/INFURA/go-did"
)

var _ did.Document = &document{}

type document struct {
	id           did.DID
	verification did.VerificationMethod
}

func (d document) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Context              []string                 `json:"@context"`
		ID                   string                   `json:"id"`
		AlsoKnownAs          []string                 `json:"alsoKnownAs,omitempty"`
		Controller           string                   `json:"controller,omitempty"`
		VerificationMethod   []did.VerificationMethod `json:"verificationMethod,omitempty"`
		Authentication       []string                 `json:"authentication,omitempty"`
		AssertionMethod      []string                 `json:"assertionMethod,omitempty"`
		KeyAgreement         []string                 `json:"keyAgreement,omitempty"`
		CapabilityInvocation []string                 `json:"capabilityInvocation,omitempty"`
		CapabilityDelegation []string                 `json:"capabilityDelegation,omitempty"`
	}{
		Context:              []string{did.JsonLdContext, d.verification.JsonLdContext()},
		ID:                   d.id.String(),
		AlsoKnownAs:          nil,
		Controller:           d.id.String(),
		VerificationMethod:   []did.VerificationMethod{d.verification},
		Authentication:       []string{d.verification.ID()},
		AssertionMethod:      []string{d.verification.ID()},
		KeyAgreement:         []string{d.verification.ID()},
		CapabilityInvocation: []string{d.verification.ID()},
		CapabilityDelegation: []string{d.verification.ID()},
	})
}

func (d document) ID() did.DID {
	return d.id
}

func (d document) Controllers() []did.DID {
	// no external controller possible for did:key
	return []did.DID{d.id}
}

func (d document) AlsoKnownAs() []url.URL {
	return nil
}

func (d document) VerificationMethods() map[string]did.VerificationMethod {
	return map[string]did.VerificationMethod{
		d.verification.ID(): d.verification,
	}
}

func (d document) Authentication() []did.VerificationMethod {
	return []did.VerificationMethod{d.verification}
}

func (d document) Assertion() []did.VerificationMethod {
	return []did.VerificationMethod{d.verification}
}

func (d document) KeyAgreement() []did.VerificationMethod {
	return []did.VerificationMethod{d.verification}
}

func (d document) CapabilityInvocation() []did.VerificationMethod {
	return []did.VerificationMethod{d.verification}
}

func (d document) CapabilityDelegation() []did.VerificationMethod {
	return []did.VerificationMethod{d.verification}
}
