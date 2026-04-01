// Package testvectors provides Wycheproof test vectors for Ed25519.
// Source: https://github.com/C2SP/wycheproof/blob/master/testvectors_v1/ed25519_test.json
// License: Apache 2.0
package testvectors

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed ed25519_test.json
var ed25519JSON []byte

// Vector is a flattened Ed25519 verify test case.
type Vector struct {
	TcId    int
	Comment string
	Flags   []string
	PK      string // 32-byte public key, hex
	Msg     string // hex
	Sig     string // 64-byte raw signature, hex
	Result  string // "valid", "invalid", "acceptable"
}

type ed25519File struct {
	TestGroups []struct {
		PublicKey struct {
			PK string `json:"pk"`
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

// Load parses and returns all Ed25519 test vectors.
func Load() ([]Vector, error) {
	var f ed25519File
	if err := json.Unmarshal(ed25519JSON, &f); err != nil {
		return nil, fmt.Errorf("testvectors: failed to parse ed25519_test.json: %w", err)
	}
	var out []Vector
	for _, g := range f.TestGroups {
		for _, t := range g.Tests {
			out = append(out, Vector{
				TcId:    t.TcId,
				Comment: t.Comment,
				Flags:   t.Flags,
				PK:      g.PublicKey.PK,
				Msg:     t.Msg,
				Sig:     t.Sig,
				Result:  t.Result,
			})
		}
	}
	return out, nil
}

// Select returns vectors that have at least one of the given flags.
func Select(vectors []Vector, flags ...string) []Vector {
	if len(flags) == 0 {
		return vectors
	}
	var out []Vector
	for _, v := range vectors {
		if hasAnyFlag(v.Flags, flags) {
			out = append(out, v)
		}
	}
	return out
}

func hasAnyFlag(have []string, want []string) bool {
	for _, w := range want {
		for _, h := range have {
			if h == w {
				return true
			}
		}
	}
	return false
}
