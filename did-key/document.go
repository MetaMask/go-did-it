package did_key

import (
	"net/url"

	"github.com/INFURA/go-did"
)

var _ did.Document = &document{}

type document struct {
	id           did.DID
	verification did.VerificationMethod
}

func (d document) MarshalJSON() ([]byte, error) {
	// TODO implement me
	panic("implement me")
}

func (d document) ID() did.DID {
	return d.id
}

func (d document) Controller() did.DID {
	// no external controller possible for did:key
	return d.id
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
