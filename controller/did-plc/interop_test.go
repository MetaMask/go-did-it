package didplcctl

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/MetaMask/go-did-it/crypto"
)

// The did:plc interoperability suite: audit logs the method's maintainers publish as the
// conformance bar for an implementation that replays a history. Each is a whole
// /:did/log/audit response, and the directory it sits in is the assertion — the logs under
// valid/ must replay cleanly, the ones under invalid/ must be rejected.
//
// They are the counterpart to the golden fixtures in chain_test.go, which are real
// histories captured from the live registry. Those check that this package accepts what
// the reference implementation produced; these check the cases a live capture cannot
// reach — a nullification signed by a key with no authority, a recovery a second past the
// window, six ways of misencoding a signature — because the registry never accepted them
// in the first place.
//
// See testdata/interop/README.md for provenance and how to refresh.

// interopReject maps each invalid vector to a substring of the error it must fail with.
// Asserting the reason and not merely the rejection is what stops a vector from passing
// for the wrong cause: every one of these logs is valid but for the single detail its
// name gives, so a coarser check would be satisfied by any bug that rejected everything.
var interopReject = map[string]string{
	"log_invalid_nullification_reused_key.json": "must be signed by a rotation key outranking",
	"log_invalid_nullification_too_slow.json":   "recovery window",
	"log_invalid_sig_b64_newline.json":          "not canonically encoded",
	"log_invalid_sig_b64_padding_bits.json":     "decoding signature",
	"log_invalid_sig_b64_padding_chars.json":    "decoding signature",
	"log_invalid_sig_der.json":                  "matches none",
	"log_invalid_sig_k256_high_s.json":          "matches none",
	"log_invalid_sig_p256_high_s.json":          "matches none",
	"log_invalid_update_nullified.json":         "not in the canonical history",
	"log_invalid_update_tombstoned.json":        "builds on tombstone",
}

func TestInteropAuditLogs(t *testing.T) {
	for _, tc := range []struct {
		dir   string
		valid bool
	}{
		{"valid", true},
		{"invalid", false},
	} {
		files, err := filepath.Glob(filepath.Join("testdata/interop", tc.dir, "*.json"))
		require.NoError(t, err)
		require.NotEmpty(t, files, "no %s vectors found", tc.dir)

		for _, file := range files {
			name := filepath.Base(file)
			t.Run(tc.dir+"/"+name, func(t *testing.T) {
				body, err := os.ReadFile(file)
				require.NoError(t, err)

				// The DID under test is the one the entries are labelled with; validation
				// checks that they all agree.
				var entries []struct {
					DID string `json:"did"`
				}
				require.NoError(t, json.Unmarshal(body, &entries))
				require.NotEmpty(t, entries)

				reg := serveFixture(t, map[string]string{"log/audit": string(body)})
				ctrl, err := reg.Controller(entries[0].DID)
				require.NoError(t, err)

				got, err := ctrl.Audit(context.Background())
				if tc.valid {
					require.NoError(t, err, "a log the maintainers publish as valid must replay")
					assert.Len(t, got, len(entries), "every entry must be reported, nullified ones included")
					return
				}
				require.Error(t, err, "a log the maintainers publish as invalid must be rejected")
				want, ok := interopReject[name]
				require.True(t, ok, "no expected rejection reason recorded for %s", name)
				assert.ErrorContains(t, err, want)
			})
		}
	}
}

// Two of the valid vectors hold rotation key lists this package would not write, and are
// worth naming because they pull in opposite directions. The empty list would be rejected by
// applying [minRotationKeys] to a fetched operation, which is why that guard covers what
// this package writes and not what it reads. The duplicate is the converse: the registry has
// never rejected one and real DIDs carry them, so it has to stay writable too, or those DIDs
// could be read but never updated. See "What this package trusts" in the package doc.
func TestInteropPinsTheReadPathLenient(t *testing.T) {
	for _, tc := range []struct{ name, why string }{
		{"log_duplicate_rotation_keys.json", "two identical rotation keys, which confer the authority of the first position only"},
		{"log_empty_rotation_keys.json", "an operation with no rotation keys at all, which nothing can ever follow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join("testdata/interop/valid", tc.name))
			require.NoError(t, err)
			var entries []struct {
				DID       string `json:"did"`
				Operation struct {
					RotationKeys []string `json:"rotationKeys"`
				} `json:"operation"`
			}
			require.NoError(t, json.Unmarshal(body, &entries))

			reg := serveFixture(t, map[string]string{"log/audit": string(body)})
			ctrl, err := reg.Controller(entries[0].DID)
			require.NoError(t, err)
			_, err = ctrl.Audit(context.Background())
			require.NoError(t, err, "must replay: it holds %s", tc.why)

			// The same key list decodes without complaint, which is the asymmetry: the
			// read path has no opinion on how many keys there are or whether they repeat.
			_, err = reg.codec.rotationKeysFromWire(entries[len(entries)-1].Operation.RotationKeys)
			require.NoError(t, err)
		})
	}

	// Of the two, only the empty list is refused on the way out, and that is this package's
	// own guard rather than the protocol's: writing one would freeze the DID for good.
	// Duplicates are written back happily, which is what lets those DIDs be updated.
	reg := NewRegistry()
	dupPub, _ := genSecp256k1(t)
	_, err := reg.codec.rotationKeysToWire([]crypto.PublicKey{dupPub, dupPub})
	assert.NoError(t, err, "duplicates must round-trip: real DIDs carry them")
	_, err = reg.codec.rotationKeysToWire(nil)
	assert.ErrorContains(t, err, "need 1 to 10 keys")
}
