package did

import (
	"encoding/json"
	"net/url"
)

type DID interface { // --> implementation for each DID type: key, pkh ..
	Method() string
	Path() string
	Query() url.Values
	Fragment() string

	Document() (Document, error)
	String() string // return the full DID URL, with path, query, fragment
}

type Document interface { // --> compact implementation, get serialized into json only if necessary
	json.Marshaler

	// ID is the identifier of the Document, which is the DID itself.
	ID() DID
	// Controller is the DID that is authorized to make changes to the Document. It's often the same as ID.
	Controller() DID

	// AlsoKnownAs returns an optional set of URL describing ???TODO
	AlsoKnownAs() []url.URL

	// VerificationMethods returns all the VerificationMethod known in the document.
	VerificationMethods() map[string]VerificationMethod

	// Authentication defines how the DID is able to authenticate, for purposes such as logging into a website
	// or engaging in any sort of challenge-response protocol.
	Authentication() []VerificationMethod

	// Assertion specifies how the DID subject is expected to express claims, such as for the purposes of issuing
	// a Verifiable Credential.
	// See https://www.w3.org/TR/vc-data-model/
	Assertion() []VerificationMethod

	// KeyAgreement specifies how an entity can generate encryption material in order to transmit confidential
	// information intended for the DID subject, such as for the purposes of establishing a secure communication channel
	// with the recipient.
	KeyAgreement() []VerificationMethod

	// CapabilityInvocation specifies a verification method that might be used by the DID subject to invoke a
	// cryptographic capability, such as the authorization to update the DID Document.
	CapabilityInvocation() []VerificationMethod

	// CapabilityDelegation specifies a mechanism that might be used by the DID subject to delegate a cryptographic
	// capability to another party, such as delegating the authority to access a specific HTTP API to a subordinate.
	CapabilityDelegation() []VerificationMethod

	// TODO: Service
	// https://www.w3.org/TR/did-extensions-properties/#service-types
}

type VerificationMethod interface { // --> implementation for each method
	json.Marshaler
	json.Unmarshaler

	// ID is a string identifier for the VerificationMethod
	ID() string
	// Type is a string identifier of a verification method.
	// See https://www.w3.org/TR/did-extensions-properties/#verification-method-types
	Type() string
	// ???? TODO
	Controller() DID

	// Verify that 'sig' is the signed hash of 'data'
	Verify(data []byte, sig []byte) bool
}
