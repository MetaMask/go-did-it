// Package testvectors provides the official BIP-340 test vectors.
// Source: https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
package testvectors

import (
	"bytes"
	"embed"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"strconv"
)

//go:embed vectors.csv
var vectorFiles embed.FS

// Vector represents one row from the BIP-340 test vector CSV.
type Vector struct {
	Index     int
	SecretKey []byte // nil if not provided (verify-only rows)
	PublicKey []byte
	AuxRand   [32]byte // all-zero if not provided (verify-only rows)
	Message   []byte
	Signature []byte
	Valid     bool
	Comment   string
}

// Load reads and parses vectors.csv, returning all test vectors.
func Load() ([]Vector, error) {
	data, err := vectorFiles.ReadFile("vectors.csv")
	if err != nil {
		return nil, err
	}

	r := csv.NewReader(bytes.NewReader(data))
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}

	var vectors []Vector
	for _, row := range rows[1:] { // skip header
		index, err := strconv.Atoi(row[0])
		if err != nil {
			return nil, err
		}

		v := Vector{
			Index:   index,
			Comment: row[7],
		}

		if row[1] != "" {
			v.SecretKey, err = hex.DecodeString(row[1])
			if err != nil {
				return nil, err
			}
		}
		v.PublicKey, err = hex.DecodeString(row[2])
		if err != nil {
			return nil, err
		}
		if row[3] != "" {
			auxRand, err := hex.DecodeString(row[3])
			if err != nil {
				return nil, err
			}
			if len(auxRand) != 32 {
				return nil, fmt.Errorf("aux_rand at index %d: expected 32 bytes, got %d", index, len(auxRand))
			}
			copy(v.AuxRand[:], auxRand)
		}
		v.Message, err = hex.DecodeString(row[4])
		if err != nil {
			return nil, err
		}
		v.Signature, err = hex.DecodeString(row[5])
		if err != nil {
			return nil, err
		}
		v.Valid = row[6] == "TRUE"

		vectors = append(vectors, v)
	}

	return vectors, nil
}
