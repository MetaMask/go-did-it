package did

import (
	"encoding/json"
	"net/url"
)

// DID is a decoded (i.e. from a string) Decentralized Identifiers.
type DID interface {
	Method() string
	Path() string
	Query() url.Values
	Fragment() string

	Document() (Document, error)
	String() string // return the full DID URL, with path, query, fragment

	Equal(DID) bool
}

// Document is the interface for a DID document. It represents the "resolved" state of a DID.
type Document interface {
	json.Marshaler

	// ID is the identifier of the Document, which is the DID itself.
	ID() DID

	// Controllers is the set of DID that is authorized to make changes to the Document. It's often the same as ID.
	Controllers() []DID

	// AlsoKnownAs returns an optional set of URL describing ???TODO
	AlsoKnownAs() []url.URL

	// VerificationMethods returns all the VerificationMethod known in the document.
	VerificationMethods() map[string]VerificationMethod

	// Authentication defines how the DID is able to authenticate, for purposes such as logging into a website
	// or engaging in any sort of challenge-response protocol.
	Authentication() []VerificationMethodSignature

	// Assertion specifies how the DID subject is expected to express claims, such as for the purposes of issuing
	// a Verifiable Credential.
	// See https://www.w3.org/TR/vc-data-model/
	Assertion() []VerificationMethodSignature

	// KeyAgreement specifies how an entity can generate encryption material in order to transmit confidential
	// information intended for the DID subject, such as for the purposes of establishing a secure communication channel
	// with the recipient.
	KeyAgreement() []VerificationMethodKeyAgreement

	// CapabilityInvocation specifies a verification method that might be used by the DID subject to invoke a
	// cryptographic capability, such as the authorization to update the DID Document.
	CapabilityInvocation() []VerificationMethodSignature

	// CapabilityDelegation specifies a mechanism that might be used by the DID subject to delegate a cryptographic
	// capability to another party, such as delegating the authority to access a specific HTTP API to a subordinate.
	CapabilityDelegation() []VerificationMethodSignature

	// TODO: Service
	// https://www.w3.org/TR/did-extensions-properties/#service-types
}

// VerificationMethod is a common interface for a cryptographic signature verification method.
// For example, Ed25519VerificationKey2020 implements the Ed25519 signature verification.
type VerificationMethod interface {
	json.Marshaler
	json.Unmarshaler

	// ID is a string identifier for the VerificationMethod. It can be referenced in a Document.
	ID() string

	// Type is a string identifier of a verification method.
	// See https://www.w3.org/TR/did-extensions-properties/#verification-method-types
	Type() string

	// Controller is a DID able to control the VerificationMethod.
	// This is not necessarily the same as for DID itself or the Document.
	Controller() string

	// JsonLdContext reports the JSON-LD context definition required for this verification method.
	JsonLdContext() string
}

// VerificationMethodSignature is a VerificationMethod implementing signature verification.
// It can be used for Authentication, Assertion, CapabilityInvocation, CapabilityDelegation
// in a Document.
type VerificationMethodSignature interface {
	VerificationMethod

	// Verify checks that 'sig' is a valid signature of 'data'.
	Verify(data []byte, sig []byte) bool
}

// VerificationMethodKeyAgreement is a VerificationMethod implementing a shared key agreement.
// It can be used for KeyAgreement in a Document.
type VerificationMethodKeyAgreement interface {
	VerificationMethod

	// TODO: function for key agreement
}
