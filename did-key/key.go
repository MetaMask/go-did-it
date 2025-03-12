package did_key

import (
	"fmt"
	"net/url"

	mbase "github.com/multiformats/go-multibase"
	varint "github.com/multiformats/go-varint"

	"github.com/INFURA/go-did"
)

type multicodecCode uint64

// Signature algorithms from the [did:key specification]
//
// [did:key specification]: https://w3c-ccg.github.io/did-method-key/#signature-method-creation-algorithm
const (
	X25519    multicodecCode = 0xec
	Ed25519   multicodecCode = 0xed
	P256      multicodecCode = 0x1200
	P384      multicodecCode = 0x1201
	P521      multicodecCode = 0x1202
	Secp256k1 multicodecCode = 0xe7
	RSA       multicodecCode = 0x1205
)

func Decode(identifier string) (did.DID, error) {
	// baseCodec, bytes, err := mbase.Decode(identifier)
	_, bytes, err := mbase.Decode(identifier)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", did.ErrInvalidDid, err)
	}
	// if baseCodec != mbase.Base58BTC {
	// 	return nil, fmt.Errorf("%w: not Base58BTC encoded", did.ErrInvalidDid)
	// }
	code, _, err := varint.FromUvarint(bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", did.ErrInvalidDid, err)
	}
	switch multicodecCode(code) {
	case Ed25519, P256, Secp256k1, RSA:
		return DidKey{bytes: string(bytes), code: multicodecCode(code)}, nil
	}
	return nil, fmt.Errorf("%w: unsupported did:key multicodec: 0x%x", did.ErrInvalidDid, code)
}

func init() {
	did.RegisterMethod("key", Decode)
}

var _ did.DID = &DidKey{}

type DidKey struct {
	// TODO: store a verification method instead
	code  multicodecCode
	bytes string // as string instead of []byte to allow the == operator
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
	// TODO implement me
	panic("implement me")
}

func (d DidKey) String() string {
	key, _ := mbase.Encode(mbase.Base58BTC, []byte(d.bytes))
	return "did:key:" + key
}
