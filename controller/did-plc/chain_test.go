package didplcctl

import (
	"context"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/p256"
)

// Replays of histories served as canned bytes rather than built through the fake
// registry: the golden logs captured from the live registry, and histories crafted by hand
// that no registry would ever have accepted. Between them they cover the chain rules —
// what a hostile or broken registry can serve, and what has to be rejected.
//
// Anything that submits an operation and reads it back belongs in roundtrip_test.go.

// The subjects of the fixtures in testdata, which hold responses captured verbatim from
// the live registry at https://plc.directory. Every CID and signature in them was produced
// by the reference implementation, so recomputing the CIDs, re-deriving the DID from the
// genesis operation and re-verifying the signatures tests this package against that
// implementation rather than against itself.
//
// See testdata/README.md for what each file is, why these two DIDs, and how to refresh
// them.
const (
	// atprotoDID uses the current operation format.
	atprotoDID = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
	// legacyDID was registered when the genesis operation still used the legacy "create"
	// format, and is followed by five operations verified against its normalized keys.
	legacyDID = "did:plc:ragtjsm2j2vknwkz3zp4oxrd"
)

// serveFixture returns a Registry backed by fixed response bodies, keyed by the path after
// the DID ("log/last", "log/audit"). It is the counterpart to the fake registry in
// fake_test.go: where that one enforces the rules a real registry enforces, this one
// serves whatever bytes a test hands it, including histories no registry would ever have
// accepted. That is what the tests below need.
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

func loadFixture(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	return string(body)
}

// auditFor serves a captured audit log for didStr, along with the last operation derived
// from it by dropping the nullified entries. Deriving that saves a fixture per endpoint
// for every case.
func auditFor(t *testing.T, name string, opts ...Option) (*Registry, string) {
	t.Helper()
	audit := loadFixture(t, name)

	var entries []struct {
		Nullified bool            `json:"nullified"`
		Operation json.RawMessage `json:"operation"`
	}
	require.NoError(t, json.Unmarshal([]byte(audit), &entries))
	ops := []json.RawMessage{}
	for _, e := range entries {
		if !e.Nullified {
			ops = append(ops, e.Operation)
		}
	}
	last, err := json.Marshal(ops[len(ops)-1])
	require.NoError(t, err)

	return serveFixture(t, map[string]string{
		"log/audit": audit,
		"log/last":  string(last),
	}, opts...), audit
}

func TestGoldenAuditLogsFromTheLiveRegistry(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fixture string
		didStr  string
		entries int
	}{
		{"current format", "audit_atproto.json", atprotoDID, 3},
		{"legacy create genesis", "audit_legacy.json", legacyDID, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg, _ := auditFor(t, tc.fixture)
			ctrl, err := reg.Controller(tc.didStr)
			require.NoError(t, err)

			entries, err := ctrl.Audit(context.Background())
			require.NoError(t, err, "a history the reference implementation accepted must validate")
			require.Len(t, entries, tc.entries)

			// Every CID in the fixture has to be reproduced from our own encoding, and the
			// DID has to be the hash of the genesis operation.
			for i, e := range entries {
				computed, err := e.prepared.cid()
				require.NoError(t, err)
				assert.Equal(t, e.CID, computed, "entry %d", i)
			}
			assert.Equal(t, tc.didStr, deriveDID(entries[0].prepared.signed))

			// Head runs the same replay when full verification is on, and must land on
			// the last entry of it.
			head, err := ctrl.Head(context.Background())
			require.NoError(t, err)
			assert.Equal(t, entries[len(entries)-1].CID, head.CID)
		})
	}
}

// A legacy create operation normalizes to two rotation keys, the recovery key then the
// signing key. Dropping the second one silently strips a key of its authority, and the
// operation that follows in this fixture is verified against that pair.
func TestLegacyCreateNormalizesBothRotationKeys(t *testing.T) {
	reg, audit := auditFor(t, "audit_legacy.json")
	ctrl, err := reg.Controller(legacyDID)
	require.NoError(t, err)

	entries, err := ctrl.Audit(context.Background())
	require.NoError(t, err)

	var raw []struct {
		Operation struct {
			SigningKey  string `json:"signingKey"`
			RecoveryKey string `json:"recoveryKey"`
			Handle      string `json:"handle"`
			Service     string `json:"service"`
		} `json:"operation"`
	}
	require.NoError(t, json.Unmarshal([]byte(audit), &raw))
	genesis := raw[0].Operation
	require.NotEmpty(t, genesis.RecoveryKey)

	require.Len(t, entries[0].prepared.rotKeys, 2)
	assert.Equal(t, []string{genesis.RecoveryKey, genesis.SigningKey}, didKeys(entries[0].prepared.rotKeys))

	require.NotNil(t, entries[0].State)
	require.Len(t, entries[0].State.RotationKeys, 2, "both keys must reach the public state")
	assert.Equal(t, genesis.RecoveryKey, didKeyString(entries[0].State.RotationKeys[0]))
	assert.Equal(t, genesis.SigningKey, didKeyString(entries[0].State.RotationKeys[1]))

	// The rest of the normalization the registry applies.
	assert.Equal(t, []string{"at://" + genesis.Handle}, entries[0].State.AlsoKnownAs)
	assert.Equal(t, genesis.SigningKey, didKeyString(entries[0].State.VerificationMethods["atproto"]))
	assert.Equal(t, genesis.Service, entries[0].State.Services["atproto_pds"].Endpoint)
	assert.Equal(t, "AtprotoPersonalDataServer", entries[0].State.Services["atproto_pds"].Type)
}

// Every key handed out in an State must be one the same package would accept back, so that
// a state read from the registry can be fed straight into an update.
func TestOpKeysRoundTrip(t *testing.T) {
	for _, fixture := range []struct{ name, didStr string }{
		{"audit_atproto.json", atprotoDID},
		{"audit_legacy.json", legacyDID},
	} {
		reg, _ := auditFor(t, fixture.name)
		ctrl, err := reg.Controller(fixture.didStr)
		require.NoError(t, err)
		entries, err := ctrl.Audit(context.Background())
		require.NoError(t, err)

		for i, e := range entries {
			if e.State == nil {
				continue
			}
			rotKeys, err := reg.codec.rotationKeysToWire(e.State.RotationKeys)
			require.NoError(t, err, "%s entry %d", fixture.name, i)
			assert.Equal(t, didKeys(e.prepared.rotKeys), didKeys(rotKeys), "%s entry %d: rotation keys must re-encode identically", fixture.name, i)

			vms, err := reg.codec.verificationMethodsToWire(e.State.VerificationMethods)
			require.NoError(t, err, "%s entry %d", fixture.name, i)
			for name, dk := range vms {
				assert.Contains(t, string(e.prepared.jsonBytes), dk, "%s entry %d: verification method %q must re-encode identically", fixture.name, i, name)
			}
		}
	}
}

// Without the genesis hash check the rest of the validation is circular: a registry can
// serve a history that is entirely self-consistent, and signed throughout by its own
// keys, for a DID that has nothing to do with it.
func TestGenesisHashAnchorsTheChainToTheDid(t *testing.T) {
	const impostor = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"

	// Relabel the log as belonging to the impostor DID, as a registry serving a forged
	// history would. The entries are now internally consistent: every CID is right, every
	// prev points where it should, every signature verifies against the preceding
	// operation's rotation keys, and the "did" metadata agrees. The only thing left that
	// can tell is that the genesis operation does not hash to the DID being asked about.
	audit := strings.ReplaceAll(loadFixture(t, "audit_atproto.json"), atprotoDID, impostor)

	served := serveFixture(t, map[string]string{"log/audit": audit}, WithFullChainVerification())
	ctrl, err := served.Controller(impostor)
	require.NoError(t, err)

	_, err = ctrl.Audit(context.Background())
	require.ErrorIs(t, err, ErrInvalidChain)
	require.ErrorContains(t, err, "hashes to "+atprotoDID)

	_, err = ctrl.Head(context.Background())
	require.ErrorIs(t, err, ErrInvalidChain, "the head lookup must be anchored too")
	require.ErrorContains(t, err, "hashes to "+atprotoDID)
}

// craftLog signs a history by hand, bypassing the authority rules, and serves it. This is
// how a hostile registry's output is modelled: the fake registry would never accept it.
type craftedOp struct {
	state  State
	signer Signer
	prev   *string
	authAs []crypto.PublicKey // rotation keys the signing code is told to accept, real rules aside
	// forkTo, when non-zero, is the 1-based index of the operation to point prev at,
	// rather than the one immediately before.
	forkTo int
	// createdAt overrides the timestamp the entry is served with, for the checks that
	// depend on how far apart operations are. Defaults to one day per operation.
	createdAt string
	isTombs   bool
	nullified bool
}

func craftHistory(t *testing.T, reg *Registry, ops []craftedOp) (didStr string, audit string) {
	t.Helper()
	type entry struct {
		DID       string          `json:"did"`
		CID       string          `json:"cid"`
		CreatedAt string          `json:"createdAt"`
		Nullified bool            `json:"nullified"`
		Operation json.RawMessage `json:"operation"`
	}
	var entries []entry
	var cids []string

	for i, c := range ops {
		if c.forkTo > 0 {
			cid := cids[c.forkTo-1]
			ops[i].prev = &cid
			c.prev = &cid
		}
		var prepared *operation
		var err error
		var authorized []rotationKey
		if len(c.authAs) > 0 {
			authorized, err = reg.codec.rotationKeysToWire(c.authAs)
			require.NoError(t, err, "authorizing operation %d", i)
		}
		switch {
		case c.isTombs:
			prepared, err = signTombstone(c.signer, *c.prev, authorized)
		case c.prev == nil:
			prepared, err = reg.codec.signGenesis(c.state, c.signer)
		default:
			prepared, err = reg.codec.signUpdate(c.state, c.signer, *c.prev, authorized)
		}
		require.NoError(t, err, "crafting operation %d", i)
		cid, err := prepared.cid()
		require.NoError(t, err)
		if i == 0 {
			didStr = deriveDID(prepared.signed)
		}
		cids = append(cids, cid)
		createdAt := c.createdAt
		if createdAt == "" {
			createdAt = fmt.Sprintf("2024-01-%02dT00:00:00.000Z", i+1)
		}
		entries = append(entries, entry{
			DID:       didStr,
			CID:       cid,
			CreatedAt: createdAt,
			Nullified: c.nullified,
			Operation: prepared.jsonBytes,
		})
		// Chain the next operation onto this one unless it names its own prev.
		if i+1 < len(ops) && ops[i+1].prev == nil && ops[i+1].forkTo == 0 {
			c := cid
			ops[i+1].prev = &c
		}
	}
	a, err := json.Marshal(entries)
	require.NoError(t, err)
	return didStr, string(a)
}

// An operation must be signed by a rotation key of the operation it builds on. Verified
// against its own keys instead, anyone could install their own rotation keys, self-sign,
// and take the DID over.
func TestOperationCannotAuthorizeItself(t *testing.T) {
	reg := NewRegistry()
	ownerPub, ownerPriv := genSecp256k1(t)
	attackerPub, attackerPriv := genSecp256k1(t)

	didStr, audit := craftHistory(t, reg, []craftedOp{
		{
			state:  State{RotationKeys: []crypto.PublicKey{ownerPub}, AlsoKnownAs: []string{"at://alice.example.com"}},
			signer: ownerPriv,
		},
		{
			// Replaces the rotation keys with the attacker's and signs with them.
			state:  State{RotationKeys: []crypto.PublicKey{attackerPub}, AlsoKnownAs: []string{"at://attacker.example.com"}},
			signer: attackerPriv,
			authAs: []crypto.PublicKey{attackerPub},
		},
	})

	served := serveFixture(t, map[string]string{"log/audit": audit}, WithFullChainVerification())
	ctrl, err := served.Controller(didStr)
	require.NoError(t, err)

	_, err = ctrl.Audit(context.Background())
	require.ErrorIs(t, err, ErrInvalidChain)
	require.ErrorContains(t, err, "signature matches none")

	_, err = ctrl.Head(context.Background())
	require.ErrorIs(t, err, ErrInvalidChain)
}

func TestTombstoneMustBeTheLastOperation(t *testing.T) {
	reg := NewRegistry()
	pub, priv := genSecp256k1(t)

	didStr, audit := craftHistory(t, reg, []craftedOp{
		{state: State{RotationKeys: []crypto.PublicKey{pub}}, signer: priv},
		{isTombs: true, signer: priv, authAs: []crypto.PublicKey{pub}},
		{state: State{RotationKeys: []crypto.PublicKey{pub}}, signer: priv, authAs: []crypto.PublicKey{pub}},
	})

	served := serveFixture(t, map[string]string{"log/audit": audit}, WithFullChainVerification())
	ctrl, err := served.Controller(didStr)
	require.NoError(t, err)

	_, err = ctrl.Audit(context.Background())
	require.ErrorIs(t, err, ErrInvalidChain)
	require.ErrorContains(t, err, "tombstone")

	_, err = ctrl.Head(context.Background())
	require.ErrorIs(t, err, ErrInvalidChain)
	require.ErrorContains(t, err, "tombstone")
}

// The nullified flags are the registry's own claim about which operations it dropped.
// Replaying the log is what holds it to that claim.
func TestNullifiedFlagsMustMatchTheReplay(t *testing.T) {
	audit := loadFixture(t, "audit_atproto.json")
	tampered := strings.Replace(audit, `"nullified": false`, `"nullified": true`, 1)
	require.NotEqual(t, audit, tampered)

	served := serveFixture(t, map[string]string{"log/audit": tampered})
	ctrl, err := served.Controller(atprotoDID)
	require.NoError(t, err)

	_, err = ctrl.Audit(context.Background())
	require.ErrorIs(t, err, ErrInvalidChain)
	require.ErrorContains(t, err, "the replay says")
}

func TestTamperedCidIsDetected(t *testing.T) {
	audit := loadFixture(t, "audit_atproto.json")
	// Swap two characters of the last CID: still a valid CID, no longer the right one.
	const realCID = "bafyreihevsrjgmed5yvvfucpqfvyygat6mozxllhomkt2x4lcbk75k6use"
	require.Contains(t, audit, realCID)
	tampered := strings.Replace(audit, realCID, "bafyreihevsrjgmed5yvvfucpqfvyygat6mozxllhomkt2x4lcbk75k6usa", 1)

	served := serveFixture(t, map[string]string{"log/audit": tampered})
	ctrl, err := served.Controller(atprotoDID)
	require.NoError(t, err)

	_, err = ctrl.Audit(context.Background())
	require.ErrorIs(t, err, ErrInvalidChain)
	require.ErrorContains(t, err, "computed")
}

func TestAuditRejectsAForeignEntry(t *testing.T) {
	audit := loadFixture(t, "audit_atproto.json")
	tampered := strings.Replace(audit, `"did": "`+atprotoDID+`"`, `"did": "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"`, 1)
	require.NotEqual(t, audit, tampered)

	served := serveFixture(t, map[string]string{"log/audit": tampered})
	ctrl, err := served.Controller(atprotoDID)
	require.NoError(t, err)

	_, err = ctrl.Audit(context.Background())
	require.ErrorIs(t, err, ErrInvalidChain)
	require.ErrorContains(t, err, "is for did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
}

// Audit reports the history whatever the Registry's verification mode: reporting it is
// the point of the call, so it is never the cheap path.
func TestAuditAlwaysValidates(t *testing.T) {
	reg, _ := auditFor(t, "audit_atproto.json")
	ctrl, err := reg.Controller("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
	require.NoError(t, err)

	_, err = ctrl.Audit(context.Background())
	require.ErrorIs(t, err, ErrInvalidChain)

	// Whereas the head lookup takes the registry at its word.
	_, err = ctrl.Head(context.Background())
	require.NoError(t, err)
}

func TestVerifySigReportsKeyAuthority(t *testing.T) {
	reg := NewRegistry()
	firstPub, firstPriv := genSecp256k1(t)
	secondPub, secondPriv := genSecp256k1(t)
	keys, err := reg.codec.rotationKeysToWire([]crypto.PublicKey{firstPub, secondPub})
	require.NoError(t, err)

	for want, signer := range map[int]Signer{0: firstPriv, 1: secondPriv} {
		msg := []byte("payload")
		sig, err := signToBase64URL(signer, msg)
		require.NoError(t, err)
		got, err := verifySig(keys, msg, sig)
		require.NoError(t, err)
		assert.Equal(t, want, got, "the index is the key's authority")
	}

	t.Run("a padded signature is refused", func(t *testing.T) {
		_, err := verifySig(keys, []byte("payload"), "AAAA=")
		require.ErrorContains(t, err, "decoding signature")
	})

	t.Run("no authorized key at all", func(t *testing.T) {
		_, err := verifySig(nil, []byte("payload"), strings.Repeat("A", 86))
		require.ErrorContains(t, err, "no rotation key is authorized")
	})
}

// did:plc requires low-S signatures (BIP-0062): of the two values of s that satisfy the
// ECDSA equation for a given message and key, only the smaller is valid. Without that rule
// an operation would have two valid signatures, and so two CIDs, either of which a
// registry could serve as the real one.
func TestHighSSignatureIsRefused(t *testing.T) {
	reg := NewRegistry()
	pub, priv, err := p256.GenerateKeyPair()
	require.NoError(t, err)
	keys, err := reg.codec.rotationKeysToWire([]crypto.PublicKey{pub})
	require.NoError(t, err)

	msg := []byte("payload")
	sig, err := signToBase64URL(priv, msg)
	require.NoError(t, err)
	_, err = verifySig(keys, msg, sig)
	require.NoError(t, err, "the signature this package produces must be low-S")

	// The high-S counterpart: same r, s replaced by n-s. It satisfies the ECDSA equation
	// just as well, which is exactly why it has to be refused explicitly.
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	require.NoError(t, err)
	half := len(raw) / 2
	s := new(big.Int).SetBytes(raw[half:])
	n := elliptic.P256().Params().N
	highS := new(big.Int).Sub(n, s)
	require.Equal(t, -1, s.Cmp(highS), "the low-S signature must be the smaller of the two")
	malleated := append(append([]byte{}, raw[:half]...), highS.FillBytes(make([]byte, half))...)

	_, err = verifySig(keys, msg, base64.RawURLEncoding.EncodeToString(malleated))
	require.ErrorIs(t, err, ErrInvalidChain)
	require.ErrorContains(t, err, "matches none")
}

// A rotation key the policy cannot decode is refused where the operation is parsed, which
// is what keeps it from reaching the signature check as a key that merely fails to match.
func TestAnUndecodableRotationKeyMakesTheOperationUnreadable(t *testing.T) {
	reg := NewRegistry()
	_, err := reg.codec.parseOp([]byte(`{"type":"plc_operation","rotationKeys":["did:key:zNotAKey"],` +
		`"verificationMethods":{},"alsoKnownAs":[],"services":{},"prev":null,"sig":"AAAA"}`))
	require.ErrorContains(t, err, "rotation key 0")
}

// The audit log is where an illegitimate recovery would show up: the registry has already
// accepted it and dropped an honest operation to make room. Replaying the log is what
// catches that, and it needs three rotation keys to be a real test — with two, any
// unauthorized recovery is also one against the top key.
func TestAuditRejectsARecoveryFromAnUnauthorizedKey(t *testing.T) {
	reg := NewRegistry()
	topPub, topPriv := genSecp256k1(t)
	midPub, midPriv := genSecp256k1(t)
	lowPub, lowPriv := genSecp256k1(t)
	keys := []crypto.PublicKey{topPub, midPub, lowPub}

	// genesis(top,mid,low) <- op signed by mid <- op signed by low, forking back to the
	// genesis operation and so nullifying mid's. low does not outrank mid, so no registry
	// should ever have accepted it.
	didStr, audit := craftHistory(t, reg, []craftedOp{
		{state: State{RotationKeys: keys}, signer: topPriv},
		{
			state:     State{RotationKeys: keys, AlsoKnownAs: []string{"at://mid.example.com"}},
			signer:    midPriv,
			authAs:    keys,
			nullified: true,
		},
		{
			state:  State{RotationKeys: keys, AlsoKnownAs: []string{"at://low.example.com"}},
			signer: lowPriv,
			authAs: keys,
			forkTo: 1,
		},
	})

	served := serveFixture(t, map[string]string{"log/audit": audit}, WithFullChainVerification())
	ctrl, err := served.Controller(didStr)
	require.NoError(t, err)

	_, err = ctrl.Audit(context.Background())
	require.ErrorIs(t, err, ErrInvalidChain)
	require.ErrorContains(t, err, "outranking")

	// And the head lookup rejects it too, which is the reason a verified head is read
	// from the full history rather than from the canonical log: with the nullified
	// operation dropped, what is left is a chain that links and verifies perfectly, and
	// nothing in it says the fork was made by a key with no authority to make it.
	_, err = ctrl.Head(context.Background())
	require.ErrorIs(t, err, ErrInvalidChain)
	require.ErrorContains(t, err, "outranking")
}

// The recovery window is the registry's own account of when things happened, but it still
// has to add up: a fork more than 72 hours after the operation it nullifies is one the
// registry should have refused.
func TestAuditRejectsALateRecovery(t *testing.T) {
	reg := NewRegistry()
	topPub, topPriv := genSecp256k1(t)
	midPub, midPriv := genSecp256k1(t)
	keys := []crypto.PublicKey{topPub, midPub}

	didStr, audit := craftHistory(t, reg, []craftedOp{
		{state: State{RotationKeys: keys}, signer: topPriv, createdAt: "2024-01-01T00:00:00.000Z"},
		{
			state:     State{RotationKeys: keys, AlsoKnownAs: []string{"at://mid.example.com"}},
			signer:    midPriv,
			authAs:    keys,
			createdAt: "2024-01-02T00:00:00.000Z",
			nullified: true,
		},
		{
			// Eight days later: the top key outranks mid, but far too late to use it.
			state:     State{RotationKeys: keys, AlsoKnownAs: []string{"at://top.example.com"}},
			signer:    topPriv,
			authAs:    keys,
			forkTo:    1,
			createdAt: "2024-01-10T00:00:00.000Z",
		},
	})

	served := serveFixture(t, map[string]string{"log/audit": audit})
	ctrl, err := served.Controller(didStr)
	require.NoError(t, err)

	_, err = ctrl.Audit(context.Background())
	require.ErrorIs(t, err, ErrInvalidChain)
	require.ErrorContains(t, err, "recovery window")
}

// Timestamps have to move forward: a recovery that claims to predate the operation it
// supersedes is the registry contradicting itself.
func TestAuditRejectsANonMonotonicRecovery(t *testing.T) {
	reg := NewRegistry()
	topPub, topPriv := genSecp256k1(t)
	midPub, midPriv := genSecp256k1(t)
	keys := []crypto.PublicKey{topPub, midPub}

	didStr, audit := craftHistory(t, reg, []craftedOp{
		{state: State{RotationKeys: keys}, signer: topPriv, createdAt: "2024-01-01T00:00:00.000Z"},
		{
			state:     State{RotationKeys: keys, AlsoKnownAs: []string{"at://mid.example.com"}},
			signer:    midPriv,
			authAs:    keys,
			createdAt: "2024-01-05T00:00:00.000Z",
			nullified: true,
		},
		{
			// Dated before the operation it nullifies, though within 72 hours of it.
			state:     State{RotationKeys: keys, AlsoKnownAs: []string{"at://top.example.com"}},
			signer:    topPriv,
			authAs:    keys,
			forkTo:    1,
			createdAt: "2024-01-03T00:00:00.000Z",
		},
	})

	served := serveFixture(t, map[string]string{"log/audit": audit})
	ctrl, err := served.Controller(didStr)
	require.NoError(t, err)

	_, err = ctrl.Audit(context.Background())
	require.ErrorIs(t, err, ErrInvalidChain)
	require.ErrorContains(t, err, "not after")
}
