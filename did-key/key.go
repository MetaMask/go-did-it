package did_key

import (
	"fmt"
	"net/url"
	"strings"

	mbase "github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"

	"github.com/INFURA/go-did"
	"github.com/INFURA/go-did/verifications/ed25519"
)

// Specification: https://w3c-ccg.github.io/did-method-key/

func Decode(identifier string) (did.DID, error) {
	const keyPrefix = "did:key:"

	if !strings.HasPrefix(identifier, keyPrefix) {
		return nil, fmt.Errorf("must start with 'did:key'")
	}

	baseCodec, bytes, err := mbase.Decode(identifier[len(keyPrefix):])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", did.ErrInvalidDid, err)
	}
	// the specification enforces that encoding
	if baseCodec != mbase.Base58BTC {
		return nil, fmt.Errorf("%w: not Base58BTC encoded", did.ErrInvalidDid)
	}
	code, read, err := varint.FromUvarint(bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", did.ErrInvalidDid, err)
	}

	d := DidKey{identifier: identifier}

	switch code {
	case ed25519.MultibaseCode:
		d.verification, err = ed25519.NewVerificationKey2020(identifier, bytes[read:], d)
	// case P256: // TODO
	// case Secp256k1: // TODO
	// case RSA: // TODO
	default:
		return nil, fmt.Errorf("%w: unsupported did:key multicodec: 0x%x", did.ErrInvalidDid, code)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", did.ErrInvalidDid, err)
	}

	return d, nil
}

func init() {
	did.RegisterMethod("key", Decode)
}

var _ did.DID = &DidKey{}

type DidKey struct {
	identifier   string // cached value
	verification did.VerificationMethod
}

func (d DidKey) Method() string {
	return "key"
}

func (d DidKey) Path() string {
	return ""
}

func (d DidKey) Query() url.Values {
	return nil
}

func (d DidKey) Fragment() string {
	return ""
}

func (d DidKey) Document() (did.Document, error) {
	return document{
		id:           d,
		verification: d.verification,
	}, nil
}

func (d DidKey) String() string {
	return d.identifier
}
