package did

import (
	"encoding/json"
	"net/url"

	"github.com/ucan-wg/go-did-it/crypto"
)

// DID is a decoded (i.e. from a string) Decentralized Identifier.
type DID interface {
	// Method returns the name of the DID method (e.g. "key" for did:key).
	Method() string

	// Document resolves the DID into a DID Document usable for e.g. signature check.
	// This can be simply expanding the DID into a Document, or involve external resolution.
	Document(opts ...ResolutionOption) (Document, error)

	// String returns the string representation of the DID.
	String() string

	// ResolutionIsExpensive returns true if resolving to a Document is an expensive operation,
	// e.g. requiring an external HTTP request. By contrast, a self-contained DID (e.g. did:key)
	// can be resolved cheaply without an external call.
	// This can be an indication whether to cache the resolved state.
	ResolutionIsExpensive() bool

	// Equal returns true if this and the given DID are the same.
	Equal(DID) bool
}

// Document is the interface for a DID document. It represents the "resolved" state of a DID.
type Document interface {
	json.Marshaler

	// Context is the set of JSON-LD context documents.
	Context() []string

	// ID is the identifier of the Document, which is the DID itself as string.
	ID() string

	// Controllers is the set of DID that is authorized to make changes to the Document. It's often the same as ID.
	Controllers() []string

	// AlsoKnownAs returns an optional set of URL describing different identifier for the DID subject,
	// for different purpose or different time.
	AlsoKnownAs() []*url.URL

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

	// Services are means of communicating or interacting with the DID subject or associated entities
	// via one or more endpoints. Examples include discovery services, agent services, social networking
	// services, file storage services, and verifiable credential repository services.
	Services() Services
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
	Verify(data []byte, sig []byte) (bool, error)
}

// VerificationMethodKeyAgreement is a VerificationMethod implementing a shared key agreement.
// It can be used for KeyAgreement in a Document.
type VerificationMethodKeyAgreement interface {
	VerificationMethod

	// PrivateKeyIsCompatible checks that the given PrivateKey is compatible with this method.
	PrivateKeyIsCompatible(local crypto.PrivateKeyKeyExchange) bool

	// KeyExchange computes the shared key using the given PrivateKey.
	KeyExchange(local crypto.PrivateKeyKeyExchange) ([]byte, error)
}
