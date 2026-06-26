package did_plc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/MetaMask/go-did-it/crypto"
	_ "github.com/MetaMask/go-did-it/crypto/all" // populate DefaultKeySet used by didKeyToPublicKey
	"github.com/MetaMask/go-did-it/crypto/ed25519"
	"github.com/MetaMask/go-did-it/crypto/secp256k1"
)

// fakeRegistry is a minimal in-memory did:plc registry for testing.
// It computes real CIDs from submitted operations so that chain validation passes.
type fakeRegistry struct {
	mu  sync.Mutex
	ops map[string][]fakeEntry // keyed by full DID string
}

type fakeEntry struct {
	DID       string          `json:"did"`
	CID       string          `json:"cid"`
	CreatedAt string          `json:"createdAt"`
	Nullified bool            `json:"nullified"`
	Operation json.RawMessage `json:"operation"`
}

func newFakeRegistry(t *testing.T) (*fakeRegistry, *Registry) {
	t.Helper()
	fr := &fakeRegistry{ops: make(map[string][]fakeEntry)}
	srv := httptest.NewServer(http.HandlerFunc(fr.handle))
	t.Cleanup(srv.Close)
	return fr, NewRegistry(WithURL(srv.URL))
}

func (fr *fakeRegistry) handle(w http.ResponseWriter, r *http.Request) {
	// Paths: /{did}  or  /{did}/log/audit
	path := strings.TrimPrefix(r.URL.Path, "/")
	did, subpath, _ := strings.Cut(path, "/")

	fr.mu.Lock()
	defer fr.mu.Unlock()

	switch {
	case r.Method == http.MethodPost && subpath == "":
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		cid, err := cidFromOpJSON(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fr.ops[did] = append(fr.ops[did], fakeEntry{
			DID:       did,
			CID:       cid,
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
			Operation: json.RawMessage(body),
		})
		w.WriteHeader(http.StatusOK)

	case r.Method == http.MethodGet && subpath == "log/audit":
		entries := fr.ops[did]
		if entries == nil {
			entries = []fakeEntry{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(entries)

	default:
		http.NotFound(w, r)
	}
}

// cidFromOpJSON computes the dag-cbor CIDv1 for a submitted JSON operation.
// Uses the same internal helpers as the client so CIDs match during Audit validation.
func cidFromOpJSON(raw json.RawMessage) (string, error) {
	var typed struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &typed); err != nil {
		return "", err
	}
	switch typed.Type {
	case "plc_operation":
		op, err := parseSignedOp(raw)
		if err != nil {
			return "", err
		}
		return computeCID(op.signed)
	case "plc_tombstone":
		ts, err := parseSignedTombstone(raw)
		if err != nil {
			return "", err
		}
		return computeCID(ts.signed)
	default:
		return "", fmt.Errorf("unknown operation type %q", typed.Type)
	}
}

// helpers

func genSecp256k1(t *testing.T) (crypto.PublicKey, *secp256k1.PrivateKey) {
	t.Helper()
	pub, priv, err := secp256k1.GenerateKeyPair()
	require.NoError(t, err)
	return pub, priv
}

func createDID(t *testing.T, reg *Registry, pub crypto.PublicKey, priv *secp256k1.PrivateKey) *Controller {
	t.Helper()
	ctrl, err := reg.Create(context.Background(), priv, Op{
		RotationKeys: []crypto.PublicKey{pub},
		AlsoKnownAs:  []string{"at://alice.example.com"},
		Services: map[string]Service{
			"atproto_pds": {Type: "AtprotoPersonalDataServer", Endpoint: "https://pds.example.com"},
		},
	})
	require.NoError(t, err)
	return ctrl
}

// tests

func TestRegistryCreate(t *testing.T) {
	_, reg := newFakeRegistry(t)
	pub, priv := genSecp256k1(t)

	ctrl, err := reg.Create(context.Background(), priv, Op{
		RotationKeys: []crypto.PublicKey{pub},
	})
	require.NoError(t, err)

	did := ctrl.DidStr()
	assert.True(t, strings.HasPrefix(did, "did:plc:"), "DID must start with did:plc:")
	assert.Equal(t, 24, len(strings.TrimPrefix(did, "did:plc:")), "MSI must be 24 chars")
}

func TestRegistryController(t *testing.T) {
	_, reg := newFakeRegistry(t)
	pub, priv := genSecp256k1(t)
	ctrl := createDID(t, reg, pub, priv)

	ctrl2 := reg.Controller(ctrl.DidStr())
	assert.Equal(t, ctrl.DidStr(), ctrl2.DidStr())
}

func TestControllerUpdate(t *testing.T) {
	fr, reg := newFakeRegistry(t)
	pub, priv := genSecp256k1(t)
	ctrl := createDID(t, reg, pub, priv)

	err := ctrl.Update(context.Background(), priv, func(op Op) (Op, error) {
		op.AlsoKnownAs = append(op.AlsoKnownAs, "at://alice.new.example.com")
		return op, nil
	})
	require.NoError(t, err)

	fr.mu.Lock()
	ops := fr.ops[ctrl.DidStr()]
	fr.mu.Unlock()
	require.Len(t, ops, 2)

	// Second op must reference the first op's CID.
	var second opJSON
	require.NoError(t, json.Unmarshal(ops[1].Operation, &second))
	assert.Equal(t, ops[0].CID, *second.Prev)
}

func TestControllerTombstone(t *testing.T) {
	fr, reg := newFakeRegistry(t)
	pub, priv := genSecp256k1(t)
	ctrl := createDID(t, reg, pub, priv)

	err := ctrl.Tombstone(context.Background(), priv)
	require.NoError(t, err)

	fr.mu.Lock()
	ops := fr.ops[ctrl.DidStr()]
	fr.mu.Unlock()
	require.Len(t, ops, 2)

	var typed struct{ Type string `json:"type"` }
	require.NoError(t, json.Unmarshal(ops[1].Operation, &typed))
	assert.Equal(t, "plc_tombstone", typed.Type)
}

func TestControllerAudit(t *testing.T) {
	_, reg := newFakeRegistry(t)
	pub, priv := genSecp256k1(t)
	ctrl := createDID(t, reg, pub, priv)

	err := ctrl.Update(context.Background(), priv, func(op Op) (Op, error) {
		op.AlsoKnownAs = append(op.AlsoKnownAs, "at://alice.new.example.com")
		return op, nil
	})
	require.NoError(t, err)

	entries, err := ctrl.Audit(context.Background())
	require.NoError(t, err)
	require.Len(t, entries, 2)

	assert.Equal(t, ctrl.DidStr(), entries[0].DID)
	assert.False(t, entries[0].Nullified)
	require.NotNil(t, entries[0].Op)
	assert.Equal(t, []string{"at://alice.example.com"}, entries[0].Op.AlsoKnownAs)

	assert.False(t, entries[1].Nullified)
	require.NotNil(t, entries[1].Op)
	assert.Contains(t, entries[1].Op.AlsoKnownAs, "at://alice.new.example.com")
}

func TestControllerAuditTombstone(t *testing.T) {
	_, reg := newFakeRegistry(t)
	pub, priv := genSecp256k1(t)
	ctrl := createDID(t, reg, pub, priv)

	require.NoError(t, ctrl.Tombstone(context.Background(), priv))

	entries, err := ctrl.Audit(context.Background())
	require.NoError(t, err)
	require.Len(t, entries, 2)
	assert.NotNil(t, entries[0].Op)
	assert.Nil(t, entries[1].Op, "tombstone entry must have nil Op")
}

func TestControllerRecover(t *testing.T) {
	fr, reg := newFakeRegistry(t)
	pub, priv := genSecp256k1(t)
	ctrl := createDID(t, reg, pub, priv)

	// Record the genesis CID before updating.
	fr.mu.Lock()
	genesisCID := fr.ops[ctrl.DidStr()][0].CID
	fr.mu.Unlock()

	// Normal update: builds on genesis.
	require.NoError(t, ctrl.Update(context.Background(), priv, func(op Op) (Op, error) {
		op.AlsoKnownAs = append(op.AlsoKnownAs, "at://alice.example.com/v2")
		return op, nil
	}))

	// Recovery: fork back to genesis, producing an op with prev=genesisCID.
	err := ctrl.Recover(context.Background(), priv, genesisCID, func(op Op) (Op, error) {
		op.AlsoKnownAs = []string{"at://alice.recovered.example.com"}
		return op, nil
	})
	require.NoError(t, err)

	fr.mu.Lock()
	ops := fr.ops[ctrl.DidStr()]
	fr.mu.Unlock()
	require.Len(t, ops, 3)

	var recovery opJSON
	require.NoError(t, json.Unmarshal(ops[2].Operation, &recovery))
	assert.Equal(t, genesisCID, *recovery.Prev, "recovery must fork from genesis CID")
}

func TestValidationErrors(t *testing.T) {
	_, reg := newFakeRegistry(t)
	pub, _ := genSecp256k1(t)
	ctx := context.Background()

	t.Run("no rotation keys", func(t *testing.T) {
		_, priv := genSecp256k1(t)
		_, err := reg.Create(ctx, priv, Op{RotationKeys: nil})
		require.ErrorContains(t, err, "rotation keys")
	})

	t.Run("too many rotation keys", func(t *testing.T) {
		_, priv := genSecp256k1(t)
		keys := make([]crypto.PublicKey, 6)
		for i := range keys {
			k, _, _ := secp256k1.GenerateKeyPair()
			keys[i] = k
		}
		_, err := reg.Create(ctx, priv, Op{RotationKeys: keys})
		require.ErrorContains(t, err, "rotation keys")
	})

	t.Run("disallowed rotation key type", func(t *testing.T) {
		_, priv := genSecp256k1(t)
		edPub, _, err := ed25519.GenerateKeyPair()
		require.NoError(t, err)
		_, err = reg.Create(ctx, priv, Op{RotationKeys: []crypto.PublicKey{edPub}})
		require.ErrorContains(t, err, "not allowed for rotation keys")
	})

	t.Run("too many verification methods", func(t *testing.T) {
		_, priv := genSecp256k1(t)
		vms := make(map[string]crypto.PublicKey, 11)
		for i := range 11 {
			vms[fmt.Sprintf("key%d", i)] = pub
		}
		_, err := reg.Create(ctx, priv, Op{
			RotationKeys:        []crypto.PublicKey{pub},
			VerificationMethods: vms,
		})
		require.ErrorContains(t, err, "verificationMethods")
	})
}
