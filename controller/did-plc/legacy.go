package did_plc

import (
	"fmt"

	"github.com/MetaMask/go-did-it/controller/did-plc/internal/dagcbor"
	"github.com/MetaMask/go-did-it/crypto"
)

// legacyCreateOp represents a deprecated genesis operation.
// Specification: https://web.plc.directory/spec/v0.1/did-plc (§ Legacy operations)
//
// Field key ordering in DAG-CBOR (canonical by encoded length, then lex):
// "sig"(3) < "prev"(4) < "type"(4,lex) < "handle"(6) < "service"(7) < "signingKey"(10) < "recoveryKey"(11)
type legacyCreateOp struct {
	Type        string  `json:"type"`
	SigningKey   string  `json:"signingKey"`
	RecoveryKey string  `json:"recoveryKey"`
	Handle      string  `json:"handle"`
	Service     string  `json:"service"`
	Prev        *string `json:"prev"`
	Sig         string  `json:"sig"`
}

func (l *legacyCreateOp) encode() (signed, unsigned []byte, err error) {
	m := map[string]any{
		"type":        "create",
		"signingKey":  l.SigningKey,
		"recoveryKey": l.RecoveryKey,
		"handle":      l.Handle,
		"service":     l.Service,
		"prev":        nil,
	}
	unsigned, err = dagcbor.Encode(m)
	if err != nil {
		return nil, nil, err
	}
	m["sig"] = l.Sig
	signed, err = dagcbor.Encode(m)
	return signed, unsigned, err
}

func (l *legacyCreateOp) toUnsignedOp() (*Op, error) {
	recoveryPub, err := didKeyToPublicKey(l.RecoveryKey)
	if err != nil {
		return nil, fmt.Errorf("recoveryKey: %w", err)
	}
	signingPub, err := didKeyToPublicKey(l.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("signingKey: %w", err)
	}
	return &Op{
		RotationKeys:        []crypto.PublicKey{recoveryPub},
		VerificationMethods: map[string]crypto.PublicKey{"atproto": signingPub},
		AlsoKnownAs:         []string{"at://" + l.Handle},
		Services:            map[string]Service{"atproto_pds": {Type: "AtprotoPersonalDataServer", Endpoint: l.Service}},
	}, nil
}
