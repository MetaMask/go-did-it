package document

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"

	"github.com/INFURA/go-did"
	"github.com/INFURA/go-did/verifications"
)

var _ did.Document = &Document{}

// Document is a did.Document decoded from an arbitrary Json Document.
// It does not know anything about the DID method used to produce that document.
type Document struct {
	context              []string
	id                   string
	alsoKnownAs          []*url.URL
	controllers          []string
	verificationMethods  map[string]did.VerificationMethod
	authentication       []did.VerificationMethodSignature
	assertion            []did.VerificationMethodSignature
	keyAgreement         []did.VerificationMethodKeyAgreement
	capabilityInvocation []did.VerificationMethodSignature
	capabilityDelegation []did.VerificationMethodSignature
}

type aux struct {
	Context              []string          `json:"@context"`
	Id                   string            `json:"id"`
	AlsoKnownAs          []string          `json:"alsoKnownAs,omitempty"`
	Controllers          json.RawMessage   `json:"controllers,omitempty"`
	VerificationMethods  []json.RawMessage `json:"verificationMethod,omitempty"`
	Authentication       []json.RawMessage `json:"authentication,omitempty"`
	Assertion            []json.RawMessage `json:"assertionMethod,omitempty"`
	KeyAgreement         []json.RawMessage `json:"keyAgreement,omitempty"`
	CapabilityInvocation []json.RawMessage `json:"capabilityInvocation,omitempty"`
	CapabilityDelegation []json.RawMessage `json:"capabilityDelegation,omitempty"`
}

// FromJsonReader decodes an arbitrary Json DID Document into a usable did.Document.
func FromJsonReader(reader io.Reader) (*Document, error) {
	// 1 MiB read limit to shut down abuse
	reader = io.LimitReader(reader, 1<<20)

	var aux aux
	err := json.NewDecoder(reader).Decode(&aux)
	if err != nil {
		return nil, err
	}
	return fromAux(&aux)
}

// FromJsonBytes decodes an arbitrary Json DID Document into a usable did.Document.
func FromJsonBytes(data []byte) (*Document, error) {
	var aux aux
	err := json.Unmarshal(data, &aux)
	if err != nil {
		return nil, err
	}
	return fromAux(&aux)
}

func fromAux(aux *aux) (*Document, error) {
	var err error
	res := Document{
		context: aux.Context,
		id:      aux.Id,
	}

	// id
	if !did.HasValidDIDSyntax(aux.Id) { // also enforce being required
		return nil, errors.New("id has invalid DID syntax")
	}

	// alsoKnownAs
	res.alsoKnownAs = make([]*url.URL, len(aux.AlsoKnownAs))
	for i, u := range aux.AlsoKnownAs {
		res.alsoKnownAs[i], err = url.Parse(u)
		if err != nil {
			return nil, fmt.Errorf("invalid alsoKnownAs: %w", err)
		}
	}

	// controller
	var s string
	var ss []string
	switch {
	case len(aux.Controllers) == 0:
		// nothing to do
	case json.Unmarshal(aux.Controllers, &s) == nil: // we have a single string
		if !did.HasValidDIDSyntax(s) {
			return nil, errors.New("controllers has invalid DID syntax")
		}
		res.controllers = []string{s}
	case json.Unmarshal(aux.Controllers, &ss) == nil: // we have an array of strings
		res.controllers = make([]string, len(ss))
		for i, s := range ss {
			if !did.HasValidDIDSyntax(s) {
				return nil, errors.New("one controllers has an invalid DID syntax")
			}
			res.controllers[i] = s
		}
	default:
		return nil, fmt.Errorf("invalid controllers")
	}

	// verificationMethods
	res.verificationMethods = map[string]did.VerificationMethod{}
	for _, m := range aux.VerificationMethods {
		vm, err := verifications.UnmarshalJSON(m)
		if err != nil {
			return nil, fmt.Errorf("invalid verificationMethods: %w", err)
		}
		res.verificationMethods[vm.ID()] = vm
	}

	// authentication
	res.authentication, err = resolveVerificationMethods[did.VerificationMethodSignature](&res, aux.Authentication)
	if err != nil {
		return nil, fmt.Errorf("invalid authentication: %w", err)
	}

	// assertion
	res.assertion, err = resolveVerificationMethods[did.VerificationMethodSignature](&res, aux.Assertion)
	if err != nil {
		return nil, fmt.Errorf("invalid assertion: %w", err)
	}

	// keyAgreement
	res.keyAgreement, err = resolveVerificationMethods[did.VerificationMethodKeyAgreement](&res, aux.KeyAgreement)
	if err != nil {
		return nil, fmt.Errorf("invalid keyAgreement: %w", err)
	}

	// capabilityInvocation
	res.capabilityInvocation, err = resolveVerificationMethods[did.VerificationMethodSignature](&res, aux.CapabilityInvocation)
	if err != nil {
		return nil, fmt.Errorf("invalid capabilityInvocation: %w", err)
	}

	// capabilityDelegation
	res.capabilityDelegation, err = resolveVerificationMethods[did.VerificationMethodSignature](&res, aux.CapabilityDelegation)
	if err != nil {
		return nil, fmt.Errorf("invalid capabilityDelegation: %w", err)
	}

	return &res, nil
}

func resolveVerificationMethods[T did.VerificationMethod](doc *Document, msgs []json.RawMessage) ([]T, error) {
	res := make([]T, len(msgs))
	for i, auth := range msgs {
		var s string
		if json.Unmarshal(auth, &s) == nil {
			// We have a string, we need to resolve it.
			// This can normally be an internal reference (with a fragment), but can also be a complete DID URL that
			// requires an external lookup. For simplicity, we don't support that (yet?).

			vm, ok := doc.verificationMethods[s]
			if !ok {
				return nil, fmt.Errorf("invalid verification method reference: %s", s)
			}
			cast, ok := vm.(T)
			if !ok {
				return nil, fmt.Errorf("resolved verification method doesn't match the expected capabilities: %T instead of %T", vm, new(T))
			}
			res[i] = cast
			continue
		}

		vm, err := verifications.UnmarshalJSON(auth)
		if err == nil {
			// we have a complete verification method
			vms, ok := vm.(T)
			if !ok {
				return nil, fmt.Errorf("verification method doesn't match the expected capabilities: %T instead of %T", vm, new(T))
			}
			res[i] = vms
			continue
		}

		return nil, fmt.Errorf("invalid verification method value: %w", err)
	}
	return res, nil
}

func (d Document) MarshalJSON() ([]byte, error) {
	var err error

	data := aux{Context: d.context, Id: d.id}

	// alsoKnownAs
	data.AlsoKnownAs = make([]string, len(d.alsoKnownAs))
	for i, u := range d.alsoKnownAs {
		data.AlsoKnownAs[i] = u.String()
	}

	// controllers
	switch {
	case len(d.controllers) == 1:
		data.Controllers, err = json.Marshal(d.controllers[0])
	case len(d.controllers) > 1:
		data.Controllers, err = json.Marshal(d.controllers)
	}
	if err != nil {
		return nil, err
	}

	// verificationMethods
	data.VerificationMethods = make([]json.RawMessage, len(d.verificationMethods))
	i := 0
	for _, method := range d.verificationMethods {
		data.VerificationMethods[i], err = json.Marshal(method)
		if err != nil {
			return nil, err
		}
		i++
	}

	// authentication
	data.Authentication, err = marshalMethods[did.VerificationMethodSignature](&d, d.authentication)
	if err != nil {
		return nil, err
	}

	// assertion
	data.Assertion, err = marshalMethods[did.VerificationMethodSignature](&d, d.assertion)
	if err != nil {
		return nil, err
	}

	// keyAgreement
	data.KeyAgreement, err = marshalMethods[did.VerificationMethodKeyAgreement](&d, d.keyAgreement)
	if err != nil {
		return nil, err
	}

	// capabilityInvocation
	data.CapabilityInvocation, err = marshalMethods[did.VerificationMethodSignature](&d, d.capabilityInvocation)
	if err != nil {
		return nil, err
	}

	// capabilityDelegation
	data.CapabilityDelegation, err = marshalMethods[did.VerificationMethodSignature](&d, d.capabilityDelegation)
	if err != nil {
		return nil, err
	}

	return json.Marshal(data)
}

func marshalMethods[T did.VerificationMethod](d *Document, methods []T) ([]json.RawMessage, error) {
	var err error
	res := make([]json.RawMessage, len(methods))
	for i, method := range methods {
		if _, ok := d.verificationMethods[method.ID()]; ok {
			res[i], err = json.Marshal(method.ID())
		} else {
			res[i], err = json.Marshal(method)
		}
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (d Document) Context() []string {
	return d.context
}

func (d Document) ID() string {
	return d.id
}

func (d Document) Controllers() []string {
	return d.controllers
}

func (d Document) AlsoKnownAs() []*url.URL {
	return d.alsoKnownAs
}

func (d Document) VerificationMethods() map[string]did.VerificationMethod {
	return d.verificationMethods
}

func (d Document) Authentication() []did.VerificationMethodSignature {
	return d.authentication
}

func (d Document) Assertion() []did.VerificationMethodSignature {
	return d.assertion
}

func (d Document) KeyAgreement() []did.VerificationMethodKeyAgreement {
	return d.keyAgreement
}

func (d Document) CapabilityInvocation() []did.VerificationMethodSignature {
	return d.capabilityInvocation
}

func (d Document) CapabilityDelegation() []did.VerificationMethodSignature {
	return d.capabilityDelegation
}
