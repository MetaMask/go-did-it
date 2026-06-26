// Package did_plc implements the controller side of the did:plc method.
//
// # Overview
//
// did:plc is a self-authenticating, recoverable DID method backed by a public
// append-only log hosted at https://plc.directory.
// Specification: https://web.plc.directory/spec/v0.1/did-plc
//
// # Usage
//
// Configure a [Registry] with [NewRegistry] and call [Registry.Create] to
// register a new DID, which returns a [Controller]. To operate on an existing
// DID, obtain a controller with [Registry.Controller].
//
//	reg := did_plc.NewRegistry()
//	ctrl, err := reg.Create(ctx, signer, did_plc.Op{
//	    RotationKeys: []crypto.PublicKey{myKey},
//	    AlsoKnownAs:  []string{"at://alice.example.com"},
//	})
//
//	ctrl := reg.Controller("did:plc:...")
//	ctrl.Update(ctx, signer, func(op did_plc.Op) (did_plc.Op, error) {
//	    op.AlsoKnownAs = append(op.AlsoKnownAs, "at://alice.new.example.com")
//	    return op, nil
//	})
//
// # Key types
//
// Rotation keys must be secp256k1 or P-256 by default. Additional algorithms
// can be allowed via [WithRotationKeySet] (e.g. for a custom registry).
// Verification-method keys may be any type supported by the did:key method.
//
// # Chain validation
//
// [Controller.Audit] fetches the full operation history and validates CID
// integrity, low-S signatures, and prev-pointer continuity.
package did_plc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/p256"
	"github.com/MetaMask/go-did-it/crypto/secp256k1"
)

// DefaultURL is the canonical PLC registry URL.
const DefaultURL = "https://plc.directory"

// Registry is a client for the did:plc HTTP registry.
type Registry struct {
	url            string
	httpClient     *http.Client
	rotationKeySet *crypto.KeySet
}

// NewRegistry returns a Registry configured by opts.
func NewRegistry(opts ...Option) *Registry {
	r := &Registry{
		url:            DefaultURL,
		httpClient:     http.DefaultClient,
		rotationKeySet: crypto.NewKeySet(secp256k1.KeyType(), p256.KeyType()),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Controller returns a Controller for an existing DID.
func (r *Registry) Controller(didStr string) *Controller {
	return &Controller{registry: r, didStr: didStr}
}

// Create registers a new DID and returns a Controller for it.
func (r *Registry) Create(ctx context.Context, signer Signer, op Op) (*Controller, error) {
	signed, err := op.sign(r, signer, nil)
	if err != nil {
		return nil, err
	}
	msi, err := signed.deriveID()
	if err != nil {
		return nil, err
	}
	didStr := "did:plc:" + msi
	if err := r.submit(ctx, didStr, signed); err != nil {
		return nil, fmt.Errorf("submitting genesis operation: %w", err)
	}
	return r.Controller(didStr), nil
}

func (r *Registry) validateRotationKeys(keys []crypto.PublicKey) error {
	if len(keys) < 1 || len(keys) > 5 {
		return fmt.Errorf("rotation keys: need 1–5 keys, got %d", len(keys))
	}
	for i, key := range keys {
		if !r.rotationKeySet.Accepts(key) {
			return fmt.Errorf("rotation key %d: key type %T not allowed for rotation keys", i, key)
		}
	}
	return nil
}

func (r *Registry) submit(ctx context.Context, didStr string, op json.Marshaler) error {
	body, err := op.MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshalling operation: %w", err)
	}
	u, err := url.JoinPath(r.url, didStr)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "go-did-it")
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("registry request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		return fmt.Errorf("registry returned HTTP %d: %s", resp.StatusCode, msg)
	}
	return nil
}

func (r *Registry) fetchAuditLog(ctx context.Context, didStr string) ([]AuditEntry, error) {
	u, err := url.JoinPath(r.url, didStr, "log", "audit")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "go-did-it")
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching audit log: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned HTTP %d", resp.StatusCode)
	}
	var raw []struct {
		DID       string          `json:"did"`
		CID       string          `json:"cid"`
		CreatedAt string          `json:"createdAt"`
		Nullified bool            `json:"nullified"`
		Operation json.RawMessage `json:"operation"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decoding audit log: %w", err)
	}
	entries := make([]AuditEntry, len(raw))
	for i, e := range raw {
		t, err := time.Parse(time.RFC3339, e.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("entry %d: invalid timestamp %q: %w", i, e.CreatedAt, err)
		}
		op, prepared, err := parseAuditEntry(e.Operation)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		entries[i] = AuditEntry{
			DID:       e.DID,
			CID:       e.CID,
			CreatedAt: t,
			Nullified: e.Nullified,
			Op:        op,
			prepared:  prepared,
		}
	}
	return entries, nil
}
