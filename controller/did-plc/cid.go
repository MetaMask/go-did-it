package did_plc

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"

	gocid "github.com/ipfs/go-cid"
	mc "github.com/multiformats/go-multicodec"
	mh "github.com/multiformats/go-multihash"
)

// base32Enc is the lowercase base32 alphabet used by multiformats (RFC 4648, no padding).
// Used for the DID MSI (method-specific identifier) derivation, which hashes directly without a CID wrapper.
var base32Enc = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// computeCID computes the CIDv1 (dag-cbor, sha2-256) of data and returns it
// as a multibase base32 string (prefix 'b').
func computeCID(data []byte) (string, error) {
	digest, err := mh.Sum(data, mh.SHA2_256, -1)
	if err != nil {
		return "", fmt.Errorf("computing multihash: %w", err)
	}
	return gocid.NewCidV1(uint64(mc.DagCbor), digest).String(), nil
}

// deriveMSI derives the 24-character method-specific identifier for a did:plc DID
// from the signed genesis operation's DAG-CBOR bytes.
//
// The MSI is the first 24 characters of the lowercase base32 encoding of the
// SHA-256 digest of the genesis operation.
func deriveMSI(genesisBytes []byte) string {
	h := sha256.Sum256(genesisBytes)
	return base32Enc.EncodeToString(h[:])[:24]
}

// validateCID checks that cidStr is a CIDv1 with the dag-cbor codec.
func validateCID(cidStr string) error {
	c, err := gocid.Decode(cidStr)
	if err != nil {
		return fmt.Errorf("invalid CID %q: %w", cidStr, err)
	}
	if c.Version() != 1 {
		return fmt.Errorf("CID %q: expected CIDv1, got v%d", cidStr, c.Version())
	}
	if c.Type() != uint64(mc.DagCbor) {
		return fmt.Errorf("CID %q: expected dag-cbor codec (0x%x), got 0x%x",
			cidStr, mc.DagCbor, c.Type())
	}
	return nil
}
