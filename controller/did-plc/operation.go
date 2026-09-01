package didplcctl

import (
	"encoding/base64"
	"fmt"

	"github.com/MetaMask/go-did-it/controller/did-plc/internal/dagcbor"
	"github.com/MetaMask/go-did-it/crypto"
)

// A single did:plc operation: the byte forms it exists in, the parts of it the protocol
// rules reason about, and the few checks it can make about itself. A [codec] is what
// produces one, from a [State] or from the wire.

// encodings holds the three byte-level forms of an operation, which the protocol requires
// to be kept apart:
//
//	unsigned   DAG-CBOR without "sig"   what the signature is computed over
//	signed     DAG-CBOR with "sig"      what the CID, and the DID, are hashed from
//	sig        unpadded base64url       the signature itself
//
// Two CBOR forms rather than one, because a signature cannot cover itself. See "How an
// operation is encoded" in the package doc for why any of it is CBOR and not the JSON the
// registry actually speaks.
type encodings struct {
	unsigned []byte
	signed   []byte
	sig      string
}

// signEncodings signs the DAG-CBOR of m and returns the encodings of the result. m gains a
// "sig" entry.
func signEncodings(m map[string]any, signer Signer) (encodings, error) {
	unsigned, err := dagcbor.Encode(m)
	if err != nil {
		return encodings{}, err
	}
	sig, err := signToBase64URL(signer, unsigned)
	if err != nil {
		return encodings{}, err
	}
	m["sig"] = sig
	signed, err := dagcbor.Encode(m)
	if err != nil {
		return encodings{}, err
	}
	return encodings{unsigned: unsigned, signed: signed, sig: sig}, nil
}

// buildEncodings returns the encodings of an operation whose signature is already known,
// as when one is read back from the registry. m gains a "sig" entry.
func buildEncodings(m map[string]any, sig string) (encodings, error) {
	unsigned, err := dagcbor.Encode(m)
	if err != nil {
		return encodings{}, err
	}
	m["sig"] = sig
	signed, err := dagcbor.Encode(m)
	if err != nil {
		return encodings{}, err
	}
	return encodings{unsigned: unsigned, signed: signed, sig: sig}, nil
}

// sigEncoding is the encoding a signature is carried in: unpadded base64url, decoded
// strictly, so that RFC 4648 §3.5 is enforced and the trailing padding bits must be zero.
//
// The specification requires exactly one spelling per signature, for the same reason it
// requires low-S. The operation's CID is the hash of its DAG-CBOR, which carries the sig
// string verbatim, so any second spelling of the same signature bytes gives the operation
// a second CID that verifies just as well. 64 bytes of signature occupy 86 base64
// characters with 4 bits left over, so a lax decoder admits 16 spellings; Go's decoder
// also silently skips '\r' and '\n', which admits unboundedly many more.
//
// Strict decoding closes the first of those and [checkCanonicalSig] closes the rest.
var sigEncoding = base64.RawURLEncoding.Strict()

// checkCanonicalSig reports whether sig is the one canonical encoding of rawSig. Decoding
// strictly is not enough on its own: Go's base64 decoder ignores '\r' and '\n' wherever
// they appear, so a signature can carry whitespace, decode to the right bytes, and still
// change the operation's CID. Re-encoding and comparing is what admits one spelling only.
func checkCanonicalSig(rawSig []byte, sig string) error {
	if canonical := sigEncoding.EncodeToString(rawSig); canonical != sig {
		return fmt.Errorf("%w: signature is not canonically encoded", ErrInvalidChain)
	}
	return nil
}

func signToBase64URL(signer Signer, message []byte) (string, error) {
	rawSig, err := signer.SignToBytes(message, crypto.WithEcdsaLowSSig())
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}
	return sigEncoding.EncodeToString(rawSig), nil
}

// operation is an operation ready to be submitted or verified: its byte encodings, plus
// the parts of it the protocol reasons about. It covers all three operation types.
type operation struct {
	encodings
	// jsonBytes is the JSON wire form: submitted to the registry, or kept verbatim from it.
	jsonBytes []byte
	// prevCID is the operation this one builds on, nil only for a genesis operation.
	prevCID *string
	// rotKeys is this operation's rotation keys, normalized (a legacy create state yields its
	// recovery key then its signing key). They are the authority for the next operation.
	rotKeys []rotationKey
	// state is the document state this operation establishes.
	state *State
	// cidCache memoizes cid().
	cidCache string
}

// isTombstone reports whether this operation deactivates the DID. A tombstone carries no
// keys of its own and establishes no state, which is why state and rotKeys are nil for one.
func (o *operation) isTombstone() bool { return o.state == nil }

// cid returns the operation's CID, which is what the next operation points at. It is
// computed from the signed encoding on first use and kept, since every chain rule that
// touches an operation asks for it.
func (o *operation) cid() (string, error) {
	if o.cidCache == "" {
		c, err := dagcbor.CID(o.signed)
		if err != nil {
			return "", err
		}
		o.cidCache = c
	}
	return o.cidCache, nil
}

// verify checks the operation's signature against the rotation keys authorized to sign
// it, and returns the index of the key that verified. That index is the key's authority:
// a lower index outranks a higher one.
func (o *operation) verify(authorized []rotationKey) (int, error) {
	return verifySig(authorized, o.unsigned, o.sig)
}

// checkGenesis verifies the operation a history starts with: it must point at no
// predecessor, must establish a state, must hash to the DID being asked about, and must
// be signed by one of its own rotation keys.
//
// The hash is the anchor every other check hangs off; see "The operation log" in the
// package doc.
func (o *operation) checkGenesis(didStr string) error {
	if o.prevCID != nil {
		return fmt.Errorf("%w: the first operation has prev=%s, expected null", ErrInvalidChain, *o.prevCID)
	}
	if o.isTombstone() {
		return fmt.Errorf("%w: the first operation is a tombstone", ErrInvalidChain)
	}
	if derived := deriveDID(o.signed); derived != didStr {
		return fmt.Errorf("%w: the genesis operation hashes to %s, not %s", ErrInvalidChain, derived, didStr)
	}
	if _, err := o.verify(o.rotKeys); err != nil {
		return fmt.Errorf("genesis operation: %w", err)
	}
	return nil
}

// verifySig checks sig (unpadded base64url) against unsigned using the given rotation
// keys, and returns the index of the key that verified. It is the primitive behind
// [operation.verify], separate only so that a signature can be checked without an
// operation to hang it on.
func verifySig(keys []rotationKey, unsigned []byte, sig string) (int, error) {
	// Refuses '=' padding and non-zero trailing padding bits; see [sigEncoding].
	rawSig, err := sigEncoding.DecodeString(sig)
	if err != nil {
		return -1, fmt.Errorf("%w: decoding signature: %w", ErrInvalidChain, err)
	}
	if err := checkCanonicalSig(rawSig, sig); err != nil {
		return -1, err
	}
	if len(rawSig) != signatureBytes {
		return -1, fmt.Errorf("%w: signature must be %d bytes, got %d", ErrInvalidChain, signatureBytes, len(rawSig))
	}
	if len(keys) == 0 {
		return -1, fmt.Errorf("%w: no rotation key is authorized to sign this operation", ErrInvalidChain)
	}
	for i, k := range keys {
		// did:plc requires low-S signatures, so a high-S one is refused even though the
		// ECDSA maths would accept it.
		if k.pub.VerifyBytes(unsigned, rawSig, crypto.WithEcdsaLowSSig()) {
			return i, nil
		}
	}
	return -1, fmt.Errorf("%w: signature matches none of the %d authorized rotation keys", ErrInvalidChain, len(keys))
}
