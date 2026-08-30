package didplcctl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/secp256k1"
)

// fakeRegistry is an in-memory did:plc registry that enforces what the canonical registry
// enforces: the strict wire schema, genesis hash anchoring, prev continuity, signature
// authority derived from the previous operation, and the recovery window.
//
// The fidelity is the point. A stub that accepts anything is how a submission the real
// registry would reject goes unnoticed in tests.
type fakeRegistry struct {
	mu      sync.Mutex
	entries map[string][]*fakeEntry
	// reg parses and verifies submissions; it never talks to the network.
	reg *Registry
	// now supplies the createdAt of accepted operations, so a test can move time.
	now func() time.Time
	// requests records "METHOD path" for every request served.
	requests []string
}

type fakeEntry struct {
	did       string
	cid       string
	createdAt time.Time
	nullified bool
	body      json.RawMessage
	prepared  *operation
}

func newFakeRegistry(t *testing.T, opts ...Option) (*fakeRegistry, *Registry) {
	t.Helper()
	fr := &fakeRegistry{
		entries: map[string][]*fakeEntry{},
		reg:     NewRegistry(),
		now:     time.Now,
	}
	srv := httptest.NewServer(http.HandlerFunc(fr.handle))
	t.Cleanup(srv.Close)
	return fr, NewRegistry(append([]Option{WithURL(srv.URL)}, opts...)...)
}

func (fr *fakeRegistry) handle(w http.ResponseWriter, r *http.Request) {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	fr.requests = append(fr.requests, r.Method+" "+r.URL.Path)
	didStr, sub, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")

	switch {
	case r.Method == http.MethodPost && sub == "":
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if code, msg := fr.accept(didStr, body); code != http.StatusOK {
			http.Error(w, msg, code)
			return
		}
		w.WriteHeader(http.StatusOK)

	case r.Method == http.MethodGet && sub == "log/last":
		canon := fr.canonical(didStr)
		if len(canon) == 0 {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, canon[len(canon)-1].body)

	case r.Method == http.MethodGet && sub == "log/audit":
		out := []map[string]any{}
		for _, e := range fr.entries[didStr] {
			out = append(out, map[string]any{
				"did":       e.did,
				"cid":       e.cid,
				"createdAt": e.createdAt.UTC().Format(time.RFC3339Nano),
				"nullified": e.nullified,
				"operation": e.body,
			})
		}
		writeJSON(w, out)

	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// canonical returns the entries still in the canonical history, in order.
func (fr *fakeRegistry) canonical(didStr string) []*fakeEntry {
	var out []*fakeEntry
	for _, e := range fr.entries[didStr] {
		if !e.nullified {
			out = append(out, e)
		}
	}
	return out
}

// accept applies the registry's acceptance rules to a submitted operation, returning the
// HTTP status it would answer with.
func (fr *fakeRegistry) accept(didStr string, body []byte) (int, string) {
	if err := strictSchema(body); err != nil {
		return http.StatusBadRequest, "schema: " + err.Error()
	}
	p, err := fr.reg.codec.parseOp(body)
	if err != nil {
		return http.StatusBadRequest, err.Error()
	}
	cid, err := p.cid()
	if err != nil {
		return http.StatusInternalServerError, err.Error()
	}

	entries := fr.entries[didStr]
	// Resubmitting an operation the registry already holds changes nothing.
	for _, e := range entries {
		if e.cid == cid {
			return http.StatusOK, ""
		}
	}

	if len(entries) == 0 {
		if p.prevCID != nil {
			return http.StatusBadRequest, "expected null prev on the first operation"
		}
		if p.isTombstone() {
			return http.StatusBadRequest, "the first operation cannot be a tombstone"
		}
		if got := deriveDID(p.signed); got != didStr {
			return http.StatusBadRequest, fmt.Sprintf("genesis hash mismatch: the operation is for %s", got)
		}
		if _, err := p.verify(p.rotKeys); err != nil {
			return http.StatusBadRequest, err.Error()
		}
	} else {
		if p.prevCID == nil {
			return http.StatusBadRequest, "misordered operation: prev is null"
		}
		canon := fr.canonical(didStr)
		idx := slices.IndexFunc(canon, func(e *fakeEntry) bool { return e.cid == *p.prevCID })
		if idx < 0 {
			return http.StatusBadRequest, "misordered operation: prev is not in the canonical history"
		}
		base := canon[idx]
		if base.prepared.isTombstone() {
			return http.StatusBadRequest, "misordered operation: prev is a tombstone"
		}
		forked := canon[idx+1:]
		if len(forked) == 0 {
			if _, err := p.verify(base.prepared.rotKeys); err != nil {
				return http.StatusBadRequest, err.Error()
			}
		} else {
			disputed := forked[0]
			signerIdx, err := disputed.prepared.verify(base.prepared.rotKeys)
			if err != nil {
				return http.StatusBadRequest, err.Error()
			}
			if signerIdx == 0 {
				return http.StatusBadRequest, "cannot nullify an operation signed by the highest-authority rotation key"
			}
			if _, err := p.verify(base.prepared.rotKeys[:signerIdx]); err != nil {
				return http.StatusBadRequest, "recovery requires a higher-authority rotation key: " + err.Error()
			}
			if lapsed := fr.now().Sub(disputed.createdAt); lapsed > recoveryWindow {
				return http.StatusBadRequest, fmt.Sprintf("late recovery: %s after the fact", lapsed)
			}
			for _, f := range forked {
				f.nullified = true
			}
		}
	}

	fr.entries[didStr] = append(fr.entries[didStr], &fakeEntry{
		did:       didStr,
		cid:       cid,
		createdAt: fr.now(),
		body:      body,
		prepared:  p,
	})
	return http.StatusOK, ""
}

// strictSchema mirrors the registry's wire schema. The collection fields are required and
// have to be an array or an object: null is rejected, which is what catches a Go nil map
// or slice marshalled straight to the wire.
func strictSchema(body []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return err
	}
	rawType, ok := m["type"]
	if !ok {
		return errors.New(`missing "type"`)
	}
	var typeStr string
	if err := json.Unmarshal(rawType, &typeStr); err != nil {
		return err
	}
	switch typeStr {
	case typeOperation:
		for _, k := range []string{"rotationKeys", "alsoKnownAs"} {
			if err := requireJSONPrefix(m, k, '['); err != nil {
				return err
			}
		}
		for _, k := range []string{"verificationMethods", "services"} {
			if err := requireJSONPrefix(m, k, '{'); err != nil {
				return err
			}
		}
		if _, ok := m["prev"]; !ok {
			return errors.New(`missing "prev"`)
		}
	case typeTombstone:
		if err := requireJSONPrefix(m, "prev", '"'); err != nil {
			return err
		}
	default:
		return fmt.Errorf("type %q cannot be submitted", typeStr)
	}
	if _, ok := m["sig"]; !ok {
		return errors.New(`missing "sig"`)
	}
	return nil
}

func requireJSONPrefix(m map[string]json.RawMessage, key string, want byte) error {
	raw, ok := m[key]
	if !ok {
		return fmt.Errorf("missing %q", key)
	}
	if len(raw) == 0 || raw[0] != want {
		return fmt.Errorf("%q must start with %q, got %s", key, string(want), raw)
	}
	return nil
}

// serveFixture returns a Registry backed by fixed response bodies, keyed by the path after
// the DID ("log", "log/last", "log/audit"). It serves histories the fake registry would
// never accept, which is exactly what the adversarial tests need.
func serveFixture(t *testing.T, bodies map[string]string, opts ...Option) *Registry {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, sub, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
		body, ok := bodies[sub]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return NewRegistry(append([]Option{WithURL(srv.URL)}, opts...)...)
}

// key helpers

func genSecp256k1(t *testing.T) (crypto.PublicKey, *secp256k1.PrivateKey) {
	t.Helper()
	pub, priv, err := secp256k1.GenerateKeyPair()
	require.NoError(t, err)
	return pub, priv
}

// createDID registers a DID whose sole rotation key is pub.
func createDID(t *testing.T, reg *Registry, pub crypto.PublicKey, priv Signer) *Controller {
	t.Helper()
	ctrl, err := reg.Create(context.Background(), priv, State{
		RotationKeys: []crypto.PublicKey{pub},
		AlsoKnownAs:  []string{"at://alice.example.com"},
		Services: map[string]Service{
			"atproto_pds": {Type: "AtprotoPersonalDataServer", Endpoint: "https://pds.example.com"},
		},
	})
	require.NoError(t, err)
	return ctrl
}
