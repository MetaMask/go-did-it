package helpers

import (
	"errors"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// Taken from crypto/ecdsa

func EncodeSignatureToASN1(r, s []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addASN1IntBytes(b, r)
		addASN1IntBytes(b, s)
	})
	return b.Bytes()
}

// addASN1IntBytes encodes in ASN.1 a positive integer represented as
// a big-endian byte slice with zero or more leading zeroes.
func addASN1IntBytes(b *cryptobyte.Builder, bytes []byte) {
	for len(bytes) > 0 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	if len(bytes) == 0 {
		b.SetError(errors.New("invalid integer"))
		return
	}
	b.AddASN1(asn1.INTEGER, func(c *cryptobyte.Builder) {
		if bytes[0]&0x80 != 0 {
			c.AddUint8(0)
		}
		c.AddBytes(bytes)
	})
}

// DecodeSignatureFromASN1 parses a DER-encoded ECDSA signature and returns
// R and S as big.Ints.
func DecodeSignatureFromASN1(sig []byte) (r, s *big.Int, err error) {
	input := cryptobyte.String(sig)
	var inner cryptobyte.String
	if !input.ReadASN1(&inner, asn1.SEQUENCE) || !input.Empty() {
		return nil, nil, errors.New("invalid ASN.1 signature")
	}
	r = new(big.Int)
	s = new(big.Int)
	if !inner.ReadASN1Integer(r) || !inner.ReadASN1Integer(s) || !inner.Empty() {
		return nil, nil, errors.New("invalid ASN.1 signature integers")
	}
	return r, s, nil
}
