package didplcctl

import (
	"crypto/sha256"
	"encoding/base32"
	"time"
)

// Constants pinned by the did:plc specification, and the one rule small enough to sit
// beside them: deriving a DID from the hash of its genesis operation, which is what makes
// the method self-authenticating.
//
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

// Limits on an operation this package writes. Every one of them mirrors a constant the
// registry enforces in assertValidIncomingOp (packages/server/src/constraints.ts of
// did-method-plc), because the registry is what will reject the submission: matching it is
// how an opaque HTTP 400 becomes a local error naming the field at fault.
//
// They are deliberately not applied to an operation read back from the registry. The
// registry itself applies them only to a submission, never when serving a stored log, so an
// operation accepted before a limit existed stays valid forever and rejecting one would
// make a real DID unreadable. See [chain.validate] and "What this package trusts" in the
// package doc.
const (
	// minRotationKeys is this package's own floor, not the protocol's: the registry accepts
	// an empty rotation key list, and an operation carrying one permanently freezes the DID,
	// since authority for the next operation comes only from this list. Refusing to write
	// one is a guard against an unrecoverable mistake, and the only place this package is
	// deliberately stricter than the registry.
	minRotationKeys = 1
	// maxRotationKeys caps the rotation key list (MAX_ROTATION_ENTRIES). Duplicates are
	// allowed: the registry has never rejected them, and real DIDs carry them, so refusing
	// would leave those DIDs unable to round-trip through [Controller.Update]. A repeated
	// key confers no extra authority — its index is its first occurrence.
	maxRotationKeys = 10

	// maxVerificationMethods caps the verificationMethods map
	// (MAX_VERIFICATION_METHOD_ENTRIES).
	maxVerificationMethods = 10

	// maxAlsoKnownAs and maxAlsoKnownAsLength bound the alsoKnownAs list, which must also be
	// free of duplicates (MAX_AKA_ENTRIES, MAX_AKA_LENGTH). The length is the longest
	// possible atproto handle, 253 characters, plus the "at://" prefix.
	//
	// maxAlsoKnownAs is the one limit here that live traffic actually reaches, so it is the
	// one a caller is most likely to hit.
	maxAlsoKnownAs       = 10
	maxAlsoKnownAsLength = 258

	// maxServices, maxServiceTypeLength and maxServiceEndpointLength bound the services map
	// (MAX_SERVICE_ENTRIES, MAX_SERVICE_TYPE_LENGTH, MAX_SERVICE_ENDPOINT_LENGTH).
	maxServices              = 10
	maxServiceTypeLength     = 256
	maxServiceEndpointLength = 512

	// maxNameLength caps a verificationMethods or services map key, which becomes a "#name"
	// fragment in the DID document (MAX_ID_LENGTH).
	maxNameLength = 32

	// maxDidKeyLength caps a verification method's did:key string (MAX_DID_KEY_LENGTH). The
	// registry applies no such limit to rotation keys, so neither does this package.
	maxDidKeyLength = 256

	// maxOperationBytes caps the DAG-CBOR encoding of a signed operation (MAX_OP_BYTES).
	maxOperationBytes = 4000

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

// base32Enc is the lowercase base32 alphabet used by multiformats (RFC 4648, no padding).
var base32Enc = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// deriveDID derives a DID from the DAG-CBOR bytes of its signed genesis operation: the
// method-specific identifier is the first msiLength characters of the lowercase base32
// encoding of the operation's SHA-256 digest.
//
// This is the rule that makes did:plc self-authenticating, and the anchor every chain
// check ultimately rests on. Note it hashes the operation directly, without the CID
// wrapper an operation's identifier carries.
func deriveDID(genesisBytes []byte) string {
	h := sha256.Sum256(genesisBytes)
	return "did:plc:" + base32Enc.EncodeToString(h[:])[:msiLength]
}
