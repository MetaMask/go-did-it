package didplcctl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/ed25519"
	"github.com/MetaMask/go-did-it/crypto/p256"
)

func TestCreate(t *testing.T) {
	fr, reg := newFakeRegistry(t)
	pub, priv := genSecp256k1(t)

	ctrl, err := reg.Create(context.Background(), priv, State{RotationKeys: []crypto.PublicKey{pub}})
	require.NoError(t, err)

	didStr := ctrl.DidStr()
	assert.True(t, strings.HasPrefix(didStr, "did:plc:"))
	assert.Len(t, strings.TrimPrefix(didStr, "did:plc:"), 24)

	// The DID has to be the hash of the genesis operation: that is the whole basis of the
	// method being self-authenticating.
	fr.mu.Lock()
	defer fr.mu.Unlock()
	entries := fr.entries[didStr]
	require.Len(t, entries, 1)
	assert.Equal(t, didStr, deriveDID(entries[0].prepared.signed))
}

// The registry treats an operation it already holds as a no-op, which is what makes a
// failed-but-actually-delivered submission safe to retry.
func TestResubmittingAnOperationIsANoOp(t *testing.T) {
	fr, reg := newFakeRegistry(t)
	pub, priv := genSecp256k1(t)
	ctrl := createDID(t, reg, pub, priv)

	fr.mu.Lock()
	body := fr.entries[ctrl.DidStr()][0].body
	fr.mu.Unlock()

	require.NoError(t, reg.submit(context.Background(), ctrl.DidStr(), body))

	fr.mu.Lock()
	defer fr.mu.Unlock()
	assert.Len(t, fr.entries[ctrl.DidStr()], 1)
}

func TestControllerRejectsInvalidDid(t *testing.T) {
	_, reg := newFakeRegistry(t)
	for _, didStr := range []string{
		"did:key:z6Mk",
		"did:plc:tooshort",
		"did:plc:ewvi7nxzyoun6zhxrhs64oi1", // '1' is not in the base32 alphabet
		"",
	} {
		_, err := reg.Controller(didStr)
		assert.Error(t, err, "should reject %q", didStr)
	}
}

func TestUpdate(t *testing.T) {
	fr, reg := newFakeRegistry(t)
	pub, priv := genSecp256k1(t)
	ctrl := createDID(t, reg, pub, priv)

	require.NoError(t, ctrl.Update(context.Background(), priv, func(state State) (State, error) {
		state.AlsoKnownAs = append(state.AlsoKnownAs, "at://alice.new.example.com")
		return state, nil
	}))

	fr.mu.Lock()
	entries := fr.entries[ctrl.DidStr()]
	fr.mu.Unlock()
	require.Len(t, entries, 2)

	var second opJSON
	require.NoError(t, json.Unmarshal(entries[1].body, &second))
	require.NotNil(t, second.Prev)
	assert.Equal(t, entries[0].cid, *second.Prev, "the update must point at the genesis CID")

	head, err := ctrl.Head(context.Background())
	require.NoError(t, err)
	assert.Equal(t, entries[1].cid, head.CID)
	assert.Equal(t, []string{"at://alice.example.com", "at://alice.new.example.com"}, head.State.AlsoKnownAs)
	// Untouched fields survive the round trip through did:key encoding.
	assert.Equal(t, "https://pds.example.com", head.State.Services["atproto_pds"].Endpoint)
}

func TestUpdateRotatesKeys(t *testing.T) {
	_, reg := newFakeRegistry(t)
	oldPub, oldPriv := genSecp256k1(t)
	newPub, newPriv := genSecp256k1(t)
	ctrl := createDID(t, reg, oldPub, oldPriv)
	ctx := context.Background()

	// The operation that installs the new key is still signed by the old one: authority
	// comes from the state being replaced.
	require.NoError(t, ctrl.Update(ctx, oldPriv, func(state State) (State, error) {
		state.RotationKeys = []crypto.PublicKey{newPub}
		return state, nil
	}))

	require.NoError(t, ctrl.Update(ctx, newPriv, func(state State) (State, error) {
		state.AlsoKnownAs = []string{"at://alice.rotated.example.com"}
		return state, nil
	}))

	err := ctrl.Update(ctx, oldPriv, func(state State) (State, error) { return state, nil })
	require.ErrorContains(t, err, "is not one of the rotation keys", "the retired key must lose its authority")
}

func TestSignerMustBeARotationKey(t *testing.T) {
	fr, reg := newFakeRegistry(t)
	pub, priv := genSecp256k1(t)
	ctrl := createDID(t, reg, pub, priv)
	_, stranger := genSecp256k1(t)

	fr.mu.Lock()
	before := len(fr.requests)
	fr.mu.Unlock()

	err := ctrl.Update(context.Background(), stranger, func(state State) (State, error) { return state, nil })
	require.ErrorContains(t, err, "is not one of the rotation keys")

	// It must fail before anything is signed and submitted: signing a state fetched from
	// a registry that does not list our key is how a DID gets handed over.
	fr.mu.Lock()
	defer fr.mu.Unlock()
	for _, req := range fr.requests[before:] {
		assert.False(t, strings.HasPrefix(req, "POST"), "nothing should have been submitted, got %s", req)
	}
}

func TestGenesisSignerMustBeARotationKey(t *testing.T) {
	_, reg := newFakeRegistry(t)
	pub, _ := genSecp256k1(t)
	_, stranger := genSecp256k1(t)

	_, err := reg.Create(context.Background(), stranger, State{RotationKeys: []crypto.PublicKey{pub}})
	require.ErrorContains(t, err, "is not one of the rotation keys")
}

// Empty collections have to reach the wire as [] and {}. Marshalled as null they fail the
// registry's schema, and they also disagree with the DAG-CBOR that was signed and hashed.
func TestSubmittedJSONUsesEmptyCollections(t *testing.T) {
	fr, reg := newFakeRegistry(t)
	pub, priv := genSecp256k1(t)

	ctrl, err := reg.Create(context.Background(), priv, State{RotationKeys: []crypto.PublicKey{pub}})
	require.NoError(t, err)

	fr.mu.Lock()
	defer fr.mu.Unlock()
	body := string(fr.entries[ctrl.DidStr()][0].body)
	assert.Contains(t, body, `"alsoKnownAs":[]`)
	assert.Contains(t, body, `"services":{}`)
	assert.Contains(t, body, `"verificationMethods":{}`)
	for _, field := range []string{"rotationKeys", "verificationMethods", "alsoKnownAs", "services"} {
		assert.NotContains(t, body, fmt.Sprintf("%q:null", field), "%s must not be null", field)
	}
	// prev, by contrast, is null on a genesis operation and has to stay that way.
	assert.Contains(t, body, `"prev":null`)
}

func TestTombstone(t *testing.T) {
	_, reg := newFakeRegistry(t)
	pub, priv := genSecp256k1(t)
	ctrl := createDID(t, reg, pub, priv)
	ctx := context.Background()

	require.NoError(t, ctrl.Tombstone(ctx, priv))

	_, err := ctrl.Head(ctx)
	require.ErrorIs(t, err, ErrDeactivated)

	entries, err := ctrl.Audit(ctx)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	assert.NotNil(t, entries[0].State)
	assert.Nil(t, entries[1].State, "a tombstone establishes no state")

	// Nothing can be built on a tombstone.
	err = ctrl.Update(ctx, priv, func(state State) (State, error) { return state, nil })
	require.ErrorIs(t, err, ErrDeactivated)
}

func TestChainVerificationPicksEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []Option
		want string
	}{
		{"by default the head lookup reads the last operation", nil, "/log/last"},
		{"full verification reads the whole history", []Option{WithFullChainVerification()}, "/log/audit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fr, reg := newFakeRegistry(t, tc.opts...)
			pub, priv := genSecp256k1(t)
			ctrl := createDID(t, reg, pub, priv)

			fr.mu.Lock()
			before := len(fr.requests)
			fr.mu.Unlock()

			_, err := ctrl.Head(context.Background())
			require.NoError(t, err)

			fr.mu.Lock()
			defer fr.mu.Unlock()
			gets := []string{}
			for _, req := range fr.requests[before:] {
				if strings.HasPrefix(req, "GET") {
					gets = append(gets, req)
				}
			}
			require.Len(t, gets, 1, "a head lookup is one request")
			assert.True(t, strings.HasSuffix(gets[0], tc.want), "got %s, want a request ending in %s", gets[0], tc.want)
		})
	}
}

// The default head lookup is unverified, but the signer check still applies.
func TestHeadOnlyStillChecksTheSigner(t *testing.T) {
	_, reg := newFakeRegistry(t)
	pub, priv := genSecp256k1(t)
	ctrl := createDID(t, reg, pub, priv)
	_, stranger := genSecp256k1(t)

	err := ctrl.Update(context.Background(), stranger, func(state State) (State, error) { return state, nil })
	require.ErrorContains(t, err, "is not one of the rotation keys")
}

func TestRecovery(t *testing.T) {
	fr, reg := newFakeRegistry(t)
	strongPub, strongPriv := genSecp256k1(t)
	weakPub, weakPriv := genSecp256k1(t)
	ctx := context.Background()

	// Rotation keys are listed in descending authority, so strong outranks weak.
	ctrl, err := reg.Create(ctx, strongPriv, State{
		RotationKeys: []crypto.PublicKey{strongPub, weakPub},
		AlsoKnownAs:  []string{"at://alice.example.com"},
	})
	require.NoError(t, err)

	fr.mu.Lock()
	genesisCID := fr.entries[ctrl.DidStr()][0].cid
	fr.mu.Unlock()

	// The weaker key takes the DID somewhere the owner does not want.
	require.NoError(t, ctrl.Update(ctx, weakPriv, func(state State) (State, error) {
		state.AlsoKnownAs = []string{"at://attacker.example.com"}
		return state, nil
	}))

	// The stronger key forks the history back to the genesis operation.
	require.NoError(t, ctrl.Recover(ctx, strongPriv, genesisCID, func(state State) (State, error) {
		state.AlsoKnownAs = []string{"at://alice.recovered.example.com"}
		return state, nil
	}))

	fr.mu.Lock()
	entries := fr.entries[ctrl.DidStr()]
	fr.mu.Unlock()
	require.Len(t, entries, 3)
	assert.False(t, entries[0].nullified)
	assert.True(t, entries[1].nullified, "the operation that was forked away must be nullified")
	assert.False(t, entries[2].nullified)

	head, err := ctrl.Head(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"at://alice.recovered.example.com"}, head.State.AlsoKnownAs)

	// The audit log, forks and all, still replays cleanly.
	audit, err := ctrl.Audit(ctx)
	require.NoError(t, err)
	require.Len(t, audit, 3)
	assert.True(t, audit[1].Nullified)
}

func TestRecoveryRequiresHigherAuthority(t *testing.T) {
	fr, reg := newFakeRegistry(t)
	strongPub, strongPriv := genSecp256k1(t)
	weakPub, weakPriv := genSecp256k1(t)
	ctx := context.Background()

	ctrl, err := reg.Create(ctx, strongPriv, State{RotationKeys: []crypto.PublicKey{strongPub, weakPub}})
	require.NoError(t, err)

	fr.mu.Lock()
	genesisCID := fr.entries[ctrl.DidStr()][0].cid
	fr.mu.Unlock()

	// An operation signed by the top key cannot be nullified by anyone.
	require.NoError(t, ctrl.Update(ctx, strongPriv, func(state State) (State, error) {
		state.AlsoKnownAs = []string{"at://alice.example.com"}
		return state, nil
	}))

	err = ctrl.Recover(ctx, strongPriv, genesisCID, func(state State) (State, error) { return state, nil })
	require.ErrorContains(t, err, "highest-authority rotation key")

	err = ctrl.Recover(ctx, weakPriv, genesisCID, func(state State) (State, error) { return state, nil })
	require.ErrorContains(t, err, "highest-authority rotation key")
}

// The authority to recover is strictly the keys ahead of the disputed signer, so a
// rotation key cannot undo its own operation, and neither can one below it. With only two
// rotation keys this collapses into the "top key" rule; it takes three to tell apart.
func TestRecoveryCannotUseTheDisputedKeyOrLower(t *testing.T) {
	fr, reg := newFakeRegistry(t)
	topPub, topPriv := genSecp256k1(t)
	midPub, midPriv := genSecp256k1(t)
	lowPub, lowPriv := genSecp256k1(t)
	ctx := context.Background()

	ctrl, err := reg.Create(ctx, topPriv, State{RotationKeys: []crypto.PublicKey{topPub, midPub, lowPub}})
	require.NoError(t, err)

	fr.mu.Lock()
	genesisCID := fr.entries[ctrl.DidStr()][0].cid
	fr.mu.Unlock()

	// The middle key makes a change.
	require.NoError(t, ctrl.Update(ctx, midPriv, func(state State) (State, error) {
		state.AlsoKnownAs = []string{"at://mid.example.com"}
		return state, nil
	}))

	refusedLocally := func(t *testing.T, signer Signer) {
		t.Helper()
		err := ctrl.Recover(ctx, signer, genesisCID, func(state State) (State, error) { return state, nil })
		require.ErrorContains(t, err, "is not one of the rotation keys")
		var regErr *RegistryError
		assert.False(t, errors.As(err, &regErr), "it must be refused before signing, not by the registry")
	}

	// It cannot then undo it: that needs a key ahead of it in the list.
	t.Run("the disputed signer itself", func(t *testing.T) { refusedLocally(t, midPriv) })
	t.Run("a key below the disputed signer", func(t *testing.T) { refusedLocally(t, lowPriv) })

	t.Run("a key above the disputed signer", func(t *testing.T) {
		require.NoError(t, ctrl.Recover(ctx, topPriv, genesisCID, func(state State) (State, error) {
			state.AlsoKnownAs = []string{"at://top.example.com"}
			return state, nil
		}))
	})
}

func TestRecoveryWindowExpires(t *testing.T) {
	fr, reg := newFakeRegistry(t)
	strongPub, strongPriv := genSecp256k1(t)
	weakPub, weakPriv := genSecp256k1(t)
	ctx := context.Background()

	// An advancing clock the test can push forward.
	clock := time.Now().Add(-30 * 24 * time.Hour)
	fr.mu.Lock()
	fr.now = func() time.Time {
		clock = clock.Add(time.Second)
		return clock
	}
	fr.mu.Unlock()

	ctrl, err := reg.Create(ctx, strongPriv, State{RotationKeys: []crypto.PublicKey{strongPub, weakPub}})
	require.NoError(t, err)

	fr.mu.Lock()
	genesisCID := fr.entries[ctrl.DidStr()][0].cid
	fr.mu.Unlock()

	require.NoError(t, ctrl.Update(ctx, weakPriv, func(state State) (State, error) {
		state.AlsoKnownAs = []string{"at://attacker.example.com"}
		return state, nil
	}))

	// Four days later the window has closed, and it is caught locally, before signing.
	err = ctrl.Recover(ctx, strongPriv, genesisCID, func(state State) (State, error) { return state, nil })
	require.ErrorContains(t, err, "recovery window")
}

func TestValidationErrors(t *testing.T) {
	_, reg := newFakeRegistry(t)
	pub, priv := genSecp256k1(t)
	ctx := context.Background()

	create := func(op State) error {
		_, err := reg.Create(ctx, priv, op)
		return err
	}

	t.Run("no rotation key", func(t *testing.T) {
		require.ErrorContains(t, create(State{}), "rotation keys")
	})

	t.Run("too many rotation keys", func(t *testing.T) {
		keys := make([]crypto.PublicKey, 6)
		for i := range keys {
			keys[i], _ = genSecp256k1(t)
		}
		require.ErrorContains(t, create(State{RotationKeys: keys}), "rotation keys")
	})

	t.Run("duplicate rotation keys", func(t *testing.T) {
		err := create(State{RotationKeys: []crypto.PublicKey{pub, pub}})
		require.ErrorContains(t, err, "forbids duplicates")
	})

	t.Run("rotation key of a refused algorithm", func(t *testing.T) {
		edPub, _, err := ed25519.GenerateKeyPair()
		require.NoError(t, err)
		err = create(State{RotationKeys: []crypto.PublicKey{edPub}})
		require.ErrorIs(t, err, crypto.ErrKeyNotAccepted, "the policy rejection must be reported as such")
	})

	t.Run("P-256 rotation key is allowed", func(t *testing.T) {
		p256Pub, p256Priv, err := p256.GenerateKeyPair()
		require.NoError(t, err)
		_, err = reg.Create(ctx, p256Priv, State{RotationKeys: []crypto.PublicKey{p256Pub}})
		require.NoError(t, err)
	})

	t.Run("too many verification methods", func(t *testing.T) {
		vms := make(map[string]crypto.PublicKey, 11)
		for i := range 11 {
			vms[fmt.Sprintf("key%d", i)] = pub
		}
		err := create(State{RotationKeys: []crypto.PublicKey{pub}, VerificationMethods: vms})
		require.ErrorContains(t, err, "verificationMethods")
	})

	t.Run("verification method name carrying a fragment marker", func(t *testing.T) {
		err := create(State{
			RotationKeys:        []crypto.PublicKey{pub},
			VerificationMethods: map[string]crypto.PublicKey{"#atproto": pub},
		})
		require.ErrorContains(t, err, "must not contain '#'")
	})

	t.Run("verification method of a refused algorithm", func(t *testing.T) {
		p384Reg := NewRegistry(WithVerificationMethodKeyPolicy(crypto.NewKeyPolicy(p256.KeyType())))
		_, err := p384Reg.codec.signGenesis(State{
			RotationKeys:        []crypto.PublicKey{pub},
			VerificationMethods: map[string]crypto.PublicKey{"atproto": pub},
		}, priv)
		require.ErrorIs(t, err, crypto.ErrKeyNotAccepted)
	})

	t.Run("alsoKnownAs without a scheme", func(t *testing.T) {
		err := create(State{RotationKeys: []crypto.PublicKey{pub}, AlsoKnownAs: []string{"alice.example.com"}})
		require.ErrorContains(t, err, "no scheme")
	})

	t.Run("service without an endpoint scheme", func(t *testing.T) {
		err := create(State{
			RotationKeys: []crypto.PublicKey{pub},
			Services:     map[string]Service{"pds": {Type: "T", Endpoint: "pds.example.com"}},
		})
		require.ErrorContains(t, err, "no scheme")
	})

	t.Run("service without a type", func(t *testing.T) {
		err := create(State{
			RotationKeys: []crypto.PublicKey{pub},
			Services:     map[string]Service{"pds": {Endpoint: "https://pds.example.com"}},
		})
		require.ErrorContains(t, err, "empty type")
	})

	t.Run("operation over the size limit", func(t *testing.T) {
		akas := make([]string, 40)
		for i := range akas {
			akas[i] = "at://" + strings.Repeat("a", 200) + fmt.Sprint(i) + ".example.com"
		}
		err := create(State{RotationKeys: []crypto.PublicKey{pub}, AlsoKnownAs: akas})
		require.ErrorContains(t, err, "over the 7500 byte limit")
	})

	t.Run("no signer", func(t *testing.T) {
		_, err := reg.Create(ctx, nil, State{RotationKeys: []crypto.PublicKey{pub}})
		require.ErrorContains(t, err, "no signer")
	})
}

func TestRegistryErrorCarriesRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "120")
		http.Error(w, "slow down", http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)

	reg := NewRegistry(WithURL(srv.URL))
	pub, priv := genSecp256k1(t)
	_, err := reg.Create(context.Background(), priv, State{RotationKeys: []crypto.PublicKey{pub}})

	var regErr *RegistryError
	require.ErrorAs(t, err, &regErr)
	assert.Equal(t, http.StatusTooManyRequests, regErr.StatusCode)
	assert.Equal(t, 2*time.Minute, regErr.RetryAfter)
	assert.Contains(t, regErr.Body, "slow down")
}

func TestParseRetryAfter(t *testing.T) {
	assert.Equal(t, time.Duration(0), parseRetryAfter(""))
	assert.Equal(t, 30*time.Second, parseRetryAfter("30"))
	assert.Equal(t, time.Duration(0), parseRetryAfter("-5"))
	assert.Equal(t, time.Duration(0), parseRetryAfter("Mon, 02 Jan 2006 15:04:05 GMT"), "a date in the past")
	assert.Equal(t, time.Duration(0), parseRetryAfter("not a value"))
	future := parseRetryAfter(time.Now().Add(time.Hour).UTC().Format(http.TimeFormat))
	assert.Greater(t, future, 55*time.Minute)
}
