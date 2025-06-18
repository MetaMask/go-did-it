package helpers

import (
	"fmt"

	mbase "github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"
)

// MultibaseDecode is a helper for decoding multibase public keys.
func MultibaseDecode(multibase string) (uint64, []byte, error) {
	baseCodec, bytes, err := mbase.Decode(multibase)
	if err != nil {
		return 0, nil, err
	}
	// the specification enforces that encoding
	if baseCodec != mbase.Base58BTC {
		return 0, nil, fmt.Errorf("not Base58BTC encoded")
	}
	code, read, err := varint.FromUvarint(bytes)
	if err != nil {
		return 0, nil, err
	}
	if read != 2 {
		return 0, nil, fmt.Errorf("unexpected multibase")
	}
	return code, bytes[read:], nil
}

// MultibaseEncode is a helper for encoding multibase public keys.
func MultibaseEncode(code uint64, bytes []byte) string {
	// can only fail with an invalid encoding, but it's hardcoded
	res, _ := mbase.Encode(mbase.Base58BTC, append(varint.ToUvarint(code), bytes...))
	return res
}
