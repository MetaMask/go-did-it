// Package testvectors provides Wycheproof test vectors for secp256k1.
// Source: https://github.com/C2SP/wycheproof/blob/master/testvectors_v1/ecdsa_secp256k1_sha256_test.json
// License: Apache 2.0
package testvectors

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed ecdsa_secp256k1_sha256_test.json
var ecdsaJSON []byte

// ECDSAVector is a single flattened ECDSA test case with its public key included.
type ECDSAVector struct {
	TcId    int
	Comment string
	Flags   []string
	// Public key coordinates (big-endian hex, zero-padded to 32 bytes).
	WX string
	WY string
	// Message and DER-encoded signature (hex).
	Msg    string
	Sig    string
	Result string // "valid", "invalid", "acceptable"
}

// HasFlag reports whether the vector carries the given flag.
func (v ECDSAVector) HasFlag(flag string) bool {
	for _, f := range v.Flags {
		if f == flag {
			return true
		}
	}
	return false
}

// HasAnyFlag reports whether the vector carries at least one of the given flags.
func (v ECDSAVector) HasAnyFlag(flags ...string) bool {
	for _, flag := range flags {
		if v.HasFlag(flag) {
			return true
		}
	}
	return false
}

// LoadECDSA parses the embedded Wycheproof ECDSA file and returns all vectors,
// flattened so each vector carries its group's public key.
func LoadECDSA() ([]ECDSAVector, error) {
	var root struct {
		TestGroups []struct {
			PublicKey struct {
				WX string `json:"wx"`
				WY string `json:"wy"`
			} `json:"publicKey"`
			Tests []struct {
				TcId    int      `json:"tcId"`
				Comment string   `json:"comment"`
				Flags   []string `json:"flags"`
				Msg     string   `json:"msg"`
				Sig     string   `json:"sig"`
				Result  string   `json:"result"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	if err := json.Unmarshal(ecdsaJSON, &root); err != nil {
		return nil, fmt.Errorf("testvectors: failed to parse ecdsa json: %w", err)
	}

	var out []ECDSAVector
	for _, group := range root.TestGroups {
		// Wycheproof sometimes includes a leading 00 byte on coordinates
		// when the high bit is set. Strip it to get the canonical 32-byte form.
		wx := stripLeadingZero(group.PublicKey.WX)
		wy := stripLeadingZero(group.PublicKey.WY)
		for _, tc := range group.Tests {
			out = append(out, ECDSAVector{
				TcId:    tc.TcId,
				Comment: tc.Comment,
				Flags:   tc.Flags,
				WX:      wx,
				WY:      wy,
				Msg:     tc.Msg,
				Sig:     tc.Sig,
				Result:  tc.Result,
			})
		}
	}
	return out, nil
}

// SelectECDSA returns all vectors that carry at least one of the given flags.
// Pass no flags to select all vectors.
func SelectECDSA(vectors []ECDSAVector, flags ...string) []ECDSAVector {
	if len(flags) == 0 {
		return vectors
	}
	var out []ECDSAVector
	for _, v := range vectors {
		if v.HasAnyFlag(flags...) {
			out = append(out, v)
		}
	}
	return out
}

// stripLeadingZero removes a single leading "00" pair from a hex string,
// which Wycheproof adds when the high bit of a coordinate is set.
func stripLeadingZero(hex string) string {
	if len(hex) == 66 && hex[:2] == "00" {
		return hex[2:]
	}
	return hex
}
