package didplcctl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/MetaMask/go-did-it"
	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/ed25519"
	"github.com/MetaMask/go-did-it/crypto/p256"
	"github.com/MetaMask/go-did-it/crypto/secp256k1"
	didplc "github.com/MetaMask/go-did-it/verifiers/did-plc"
)

// DefaultRegistry is the canonical PLC registry URL.
const DefaultRegistry = didplc.DefaultRegistry

// ChainVerification selects how much of the operation log is fetched and verified
// before an operation is signed.
type ChainVerification int

const (
	// VerifyFullChain fetches the canonical operation log (GET /:did/log) and verifies
	// it from the genesis operation: the DID must be the hash of the genesis operation,
	// each operation must point at its predecessor and be signed by one of that
	// predecessor's rotation keys, and a tombstone may only appear last. This makes the
	// state self-authenticating, so the registry is not trusted to report it honestly.
	// It costs one response proportional to the length of the history.
	//
	// This is the default.
	VerifyFullChain ChainVerification = iota

	// VerifyHeadOnly fetches only the latest operation (GET /:did/log/last) and computes
	// its CID locally. One small response whatever the length of the history, but the
	// registry's answer is taken on trust: nothing ties the operation it returns to the
	// DID, and a forged history is not detected.
	//
	// [Controller.Audit] always performs full validation regardless of this setting.
	VerifyHeadOnly
)

// Registry is a client for the did:plc HTTP registry, and the one place this package is
// configured: the endpoint to talk to, how much of a history to verify, and which key
// algorithms to accept. Everything that builds, signs, parses or submits an operation
// does so under a Registry, which is why those methods hang off it even where they touch
// no network.
type Registry struct {
	url          string
	httpClient   did.HttpClient
	verification ChainVerification
	// rotationPolicy is the algorithms accepted for rotation keys, vmPolicy those accepted
	// for verification methods.
	rotationPolicy *crypto.KeyPolicy
	vmPolicy       *crypto.KeyPolicy
}

// NewRegistry returns a Registry configured by opts.
func NewRegistry(opts ...Option) *Registry {
	r := &Registry{
		url:          DefaultRegistry,
		httpClient:   http.DefaultClient,
		verification: VerifyFullChain,
		// The specification allows only these two algorithms for rotation keys.
		rotationPolicy: crypto.NewKeyPolicy(secp256k1.KeyType(), p256.KeyType()),
		// It allows any did:key algorithm for verification methods; these three are the
		// ones that occur in practice.
		vmPolicy: crypto.NewKeyPolicy(secp256k1.KeyType(), p256.KeyType(), ed25519.KeyType()),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Controller returns a Controller for an existing DID. It fails if didStr is not a
// syntactically valid did:plc DID.
func (r *Registry) Controller(didStr string) (*Controller, error) {
	d, err := didplc.Decode(didStr)
	if err != nil {
		return nil, err
	}
	plc, ok := d.(didplc.DidPlc)
	if !ok {
		return nil, fmt.Errorf("%w: not a did:plc DID: %q", did.ErrInvalidDid, didStr)
	}
	return &Controller{registry: r, did: plc}, nil
}

// Create registers a new DID and returns a Controller for it. The DID is derived from
// the hash of the genesis operation, so it is not known before signing.
//
// signer must hold one of op.RotationKeys: a genesis operation is self-signed.
//
// Submitting a genesis operation that the registry already holds verbatim succeeds
// without changing anything, so Create is safe to retry.
func (r *Registry) Create(ctx context.Context, signer Signer, op Op) (*Controller, error) {
	prepared, err := r.signGenesis(op, signer)
	if err != nil {
		return nil, err
	}
	didStr := deriveDID(prepared.signed)
	if err := r.submit(ctx, didStr, prepared.jsonBytes); err != nil {
		return nil, fmt.Errorf("submitting genesis operation: %w", err)
	}
	return r.Controller(didStr)
}

// maxResponseBytes caps how much of a registry response is read, to bound memory use on a
// hostile or malfunctioning registry. It is generous enough for the operation log of any
// plausible DID (roughly ten thousand operations).
const maxResponseBytes = 8 << 20

// submit POSTs an operation to the registry (POST /:did).
func (r *Registry) submit(ctx context.Context, didStr string, body []byte) error {
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
		return registryError(resp)
	}
	return nil
}

// fetch GETs r.url joined with segments, and returns the body.
func (r *Registry) fetch(ctx context.Context, segments ...string) ([]byte, error) {
	u, err := url.JoinPath(r.url, segments...)
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
		return nil, fmt.Errorf("registry request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, registryError(resp)
	}
	// Read one byte past the cap so that hitting it is reported as such, instead of
	// surfacing as a truncated-JSON error.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading registry response: %w", err)
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("registry response exceeds %d bytes", maxResponseBytes)
	}
	return body, nil
}

// fetchLastOp retrieves the latest operation only (GET /:did/log/last). Nothing ties the
// answer to the DID, so it is only as trustworthy as the registry; see [VerifyHeadOnly].
func (r *Registry) fetchLastOp(ctx context.Context, didStr string) (*preparedOp, error) {
	body, err := r.fetch(ctx, didStr, "log", "last")
	if err != nil {
		return nil, err
	}
	p, err := r.parseOp(body)
	if err != nil {
		return nil, fmt.Errorf("decoding last operation: %w", err)
	}
	return p, nil
}

// fetchOperationLog retrieves the canonical operation log (GET /:did/log), which excludes
// operations nullified by a recovery. It is everything
// [validateOperationLog] needs to verify the DID's state from its genesis.
func (r *Registry) fetchOperationLog(ctx context.Context, didStr string) ([]*preparedOp, error) {
	body, err := r.fetch(ctx, didStr, "log")
	if err != nil {
		return nil, err
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decoding operation log: %w", err)
	}
	ops := make([]*preparedOp, len(raw))
	for i, entry := range raw {
		ops[i], err = r.parseOp(entry)
		if err != nil {
			return nil, fmt.Errorf("decoding operation %d: %w", i, err)
		}
	}
	return ops, nil
}

// fetchAuditLog retrieves the full audit log (GET /:did/log/audit), including the
// operations nullified by a recovery and the registry's timestamps.
func (r *Registry) fetchAuditLog(ctx context.Context, didStr string) ([]AuditEntry, error) {
	body, err := r.fetch(ctx, didStr, "log", "audit")
	if err != nil {
		return nil, err
	}
	var raw []struct {
		DID       string          `json:"did"`
		CID       string          `json:"cid"`
		CreatedAt string          `json:"createdAt"`
		Nullified bool            `json:"nullified"`
		Operation json.RawMessage `json:"operation"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decoding audit log: %w", err)
	}
	entries := make([]AuditEntry, len(raw))
	for i, e := range raw {
		t, err := time.Parse(time.RFC3339, e.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("entry %d: invalid timestamp %q: %w", i, e.CreatedAt, err)
		}
		p, err := r.parseOp(e.Operation)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		entries[i] = AuditEntry{
			DID:       e.DID,
			CID:       e.CID,
			CreatedAt: t,
			Nullified: e.Nullified,
			Op:        p.op,
			prepared:  p,
		}
	}
	return entries, nil
}

// RegistryError is a non-2xx response from the registry.
type RegistryError struct {
	StatusCode int
	// Body is the response body, truncated.
	Body string
	// RetryAfter is the delay requested by a Retry-After header, or zero if the registry
	// did not send one. The canonical registry rate-limits both reads and writes.
	RetryAfter time.Duration
}

func (e *RegistryError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("registry returned HTTP %d (retry after %s): %s", e.StatusCode, e.RetryAfter, e.Body)
	}
	return fmt.Sprintf("registry returned HTTP %d: %s", e.StatusCode, e.Body)
}

func registryError(resp *http.Response) error {
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	return &RegistryError{
		StatusCode: resp.StatusCode,
		Body:       string(msg),
		RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
	}
}

// parseRetryAfter reads a Retry-After header in either of its two forms (RFC 9110
// §10.2.3): a delay in seconds, or an HTTP date.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
