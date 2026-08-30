package didplcctl

import "time"

// Constants pinned by the did:plc specification.
// Specification: https://web.plc.directory/spec/v0.1/did-plc

// Operation type discriminators, as they appear on the wire. "create" is the deprecated
// genesis format, which can be read but never written.
const (
	typeOperation    = "plc_operation"
	typeTombstone    = "plc_tombstone"
	typeLegacyCreate = "create"
)

// didKeyPrefix is what every key in an operation is prefixed with: rotation keys and
// verification methods are both carried as did:key strings.
const didKeyPrefix = "did:key:"

const (
	// minRotationKeys and maxRotationKeys bound the rotation key list, which must also be
	// free of duplicates. The keys are ordered by descending authority.
	minRotationKeys = 1
	maxRotationKeys = 5

	// maxVerificationMethods caps the verificationMethods map.
	maxVerificationMethods = 10

	// maxOperationBytes caps the DAG-CBOR encoding of a signed operation.
	maxOperationBytes = 7500

	// signatureBytes is the length of a raw signature: 32-byte r then 32-byte s,
	// big-endian, canonicalized to low-S per BIP-0062, carried as unpadded base64url.
	signatureBytes = 64

	// msiLength is how many characters of the base32-encoded SHA-256 digest of the genesis
	// operation form the method-specific identifier of a DID.
	msiLength = 24

	// recoveryWindow is how long a higher-authority rotation key is given to rewrite
	// history, counted from the operation it nullifies.
	recoveryWindow = 72 * time.Hour
)
