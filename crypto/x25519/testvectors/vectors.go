// Package testvectors provides Wycheproof test vectors for X25519.
// Source: https://github.com/C2SP/wycheproof/blob/master/testvectors_v1/x25519_test.json
// License: Apache 2.0
package testvectors

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed x25519_test.json
var x25519JSON []byte

// Vector is an X25519 key exchange test case.
type Vector struct {
	TcId    int
	Comment string
	Flags   []string
	Public  string // 32-byte public key, hex, little-endian
	Private string // 32-byte private key, hex, little-endian
	Shared  string // 32-byte expected shared secret, hex, little-endian
	Result  string // "valid", "acceptable"
}

type x25519File struct {
	TestGroups []struct {
		Tests []struct {
			TcId    int      `json:"tcId"`
			Comment string   `json:"comment"`
			Flags   []string `json:"flags"`
			Public  string   `json:"public"`
			Private string   `json:"private"`
			Shared  string   `json:"shared"`
			Result  string   `json:"result"`
		} `json:"tests"`
	} `json:"testGroups"`
}

// Load parses and returns all X25519 test vectors.
func Load() ([]Vector, error) {
	var f x25519File
	if err := json.Unmarshal(x25519JSON, &f); err != nil {
		return nil, fmt.Errorf("testvectors: failed to parse x25519_test.json: %w", err)
	}
	var out []Vector
	for _, g := range f.TestGroups {
		for _, t := range g.Tests {
			out = append(out, Vector{
				TcId:    t.TcId,
				Comment: t.Comment,
				Flags:   t.Flags,
				Public:  t.Public,
				Private: t.Private,
				Shared:  t.Shared,
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
