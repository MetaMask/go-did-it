package did_plc

import (
	"encoding/json"
	"fmt"

	"github.com/MetaMask/go-did-it/controller/did-plc/internal/dagcbor"
)

type signedTombstone struct {
	unsigned  []byte
	signed    []byte
	jsonBytes []byte
	prevCID   string
	signature string
}

type signedTombstoneJSON struct {
	Type string `json:"type"`
	Prev string `json:"prev"`
	Sig  string `json:"sig"`
}

func signTombstone(signer Signer, prevCID string) (*signedTombstone, error) {
	// Validate CID format without converting to a link; prev is string-encoded per spec.
	if err := validateCID(prevCID); err != nil {
		return nil, fmt.Errorf("invalid prevCID: %w", err)
	}
	m := map[string]any{"type": "plc_tombstone", "prev": prevCID}
	unsignedBytes, err := dagcbor.Encode(m)
	if err != nil {
		return nil, err
	}
	sig, err := signToBase64URL(signer, unsignedBytes)
	if err != nil {
		return nil, err
	}
	m["sig"] = sig
	signedBytes, err := dagcbor.Encode(m)
	if err != nil {
		return nil, err
	}
	jsonBytes, err := json.Marshal(signedTombstoneJSON{Type: "plc_tombstone", Prev: prevCID, Sig: sig})
	if err != nil {
		return nil, err
	}
	return &signedTombstone{
		unsigned:  unsignedBytes,
		signed:    signedBytes,
		jsonBytes: jsonBytes,
		prevCID:   prevCID,
		signature: sig,
	}, nil
}

func parseSignedTombstone(data json.RawMessage) (*signedTombstone, error) {
	var raw signedTombstoneJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if raw.Type != "plc_tombstone" {
		return nil, fmt.Errorf("expected type %q, got %q", "plc_tombstone", raw.Type)
	}
	// Validate CID format; prev is string-encoded per spec, not a binary link.
	if err := validateCID(raw.Prev); err != nil {
		return nil, fmt.Errorf("invalid prev CID: %w", err)
	}
	m := map[string]any{"type": "plc_tombstone", "prev": raw.Prev}
	unsignedBytes, err := dagcbor.Encode(m)
	if err != nil {
		return nil, err
	}
	m["sig"] = raw.Sig
	signedBytes, err := dagcbor.Encode(m)
	if err != nil {
		return nil, err
	}
	return &signedTombstone{
		unsigned:  unsignedBytes,
		signed:    signedBytes,
		jsonBytes: data,
		prevCID:   raw.Prev,
		signature: raw.Sig,
	}, nil
}

func (ts *signedTombstone) MarshalJSON() ([]byte, error) { return ts.jsonBytes, nil }
