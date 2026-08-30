package didplcctl

import (
	"encoding/json"
	"fmt"
)

// The codec for plc_tombstone, the operation that permanently deactivates a DID. It
// carries no keys and establishes no state, so the resulting preparedOp has neither.

type tombstoneJSON struct {
	Type string `json:"type"`
	Prev string `json:"prev"`
	Sig  string `json:"sig"`
}

// cborMap returns the DAG-CBOR form of the tombstone, without "sig". prev is
// string-encoded per the spec, not a binary CID link, and is not nullable.
func (t tombstoneJSON) cborMap() map[string]any {
	return map[string]any{"type": typeTombstone, "prev": t.Prev}
}

// signTombstone builds the operation that deactivates a DID. authorized is the rotation
// key set of the operation being tombstoned, which bounds who may sign.
func signTombstone(signer Signer, prevCID string, authorized []rotationKey) (*preparedOp, error) {
	if err := validateCID(prevCID); err != nil {
		return nil, fmt.Errorf("invalid prev CID: %w", err)
	}
	if err := checkSignerAuthorized(signer, authorized); err != nil {
		return nil, err
	}
	t := tombstoneJSON{Type: typeTombstone, Prev: prevCID}
	enc, err := signEncodings(t.cborMap(), signer)
	if err != nil {
		return nil, err
	}
	t.Sig = enc.sig
	jsonBytes, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}
	return &preparedOp{encodings: enc, jsonBytes: jsonBytes, prevCID: &prevCID}, nil
}

func parseTombstone(data json.RawMessage) (*preparedOp, error) {
	var raw tombstoneJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if raw.Type != typeTombstone {
		return nil, fmt.Errorf("expected type %q, got %q", typeTombstone, raw.Type)
	}
	if err := validateCID(raw.Prev); err != nil {
		return nil, fmt.Errorf("invalid prev CID: %w", err)
	}
	enc, err := buildEncodings(raw.cborMap(), raw.Sig)
	if err != nil {
		return nil, err
	}
	return &preparedOp{encodings: enc, jsonBytes: data, prevCID: &raw.Prev}, nil
}
