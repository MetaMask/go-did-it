package didkey

import (
	"encoding/json"
	"net/url"

	"github.com/MetaMask/go-did-it"
)

var _ did.Document = &document{}

type document struct {
	id           string
	signature    did.VerificationMethodSignature
	keyAgreement did.VerificationMethodKeyAgreement
}

func (d document) MarshalJSON() ([]byte, error) {
	// It's unclear where the KeyAgreement should be.
	// Maybe it doesn't matter, but the spec contradicts itself.
	// See https://github.com/w3c-ccg/did-key-spec/issues/71

	vms := []did.VerificationMethod{d.signature}
	if d.signature != did.VerificationMethod(d.keyAgreement) {
		vms = append(vms, d.keyAgreement)
	}

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
		Context:              d.Context(),
		ID:                   d.id,
		AlsoKnownAs:          nil,
		VerificationMethod:   vms,
		Authentication:       []string{d.signature.ID()},
		AssertionMethod:      []string{d.signature.ID()},
		KeyAgreement:         []string{d.keyAgreement.ID()},
		CapabilityInvocation: []string{d.signature.ID()},
		CapabilityDelegation: []string{d.signature.ID()},
	})
}

func (d document) Context() []string {
	return stringSet(
		did.JsonLdContext,
		d.signature.JsonLdContext(),
		d.keyAgreement.JsonLdContext(),
	)
}

func (d document) ID() string {
	return d.id
}

func (d document) Controllers() []string {
	// no controller for did:key, no changes are possible
	return nil
}

func (d document) AlsoKnownAs() []*url.URL {
	return nil
}

func (d document) VerificationMethods() map[string]did.VerificationMethod {
	if d.signature == did.VerificationMethod(d.keyAgreement) {
		return map[string]did.VerificationMethod{
			d.signature.ID(): d.signature,
		}
	}
	return map[string]did.VerificationMethod{
		d.signature.ID():    d.signature,
		d.keyAgreement.ID(): d.keyAgreement,
	}
}

func (d document) Authentication() []did.VerificationMethodSignature {
	return []did.VerificationMethodSignature{d.signature}
}

func (d document) Assertion() []did.VerificationMethodSignature {
	return []did.VerificationMethodSignature{d.signature}
}

func (d document) KeyAgreement() []did.VerificationMethodKeyAgreement {
	return []did.VerificationMethodKeyAgreement{d.keyAgreement}
}

func (d document) CapabilityInvocation() []did.VerificationMethodSignature {
	return []did.VerificationMethodSignature{d.signature}
}

func (d document) CapabilityDelegation() []did.VerificationMethodSignature {
	return []did.VerificationMethodSignature{d.signature}
}

func (d document) Services() did.Services {
	return nil
}

func stringSet(values ...string) []string {
	res := make([]string, 0, len(values))
loop:
	for _, str := range values {
		for _, item := range res {
			if str == item {
				continue loop
			}
		}
		res = append(res, str)
	}
	return res
}
