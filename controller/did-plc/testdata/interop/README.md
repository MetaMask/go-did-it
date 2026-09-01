# did:plc interoperability vectors

The conformance suite the did:plc maintainers publish for implementations that replay an
operation log. Each file is a whole `GET /:did/log/audit` response, and the directory it
sits in is the assertion: everything under `valid/` must replay cleanly, everything under
`invalid/` must be rejected. `TestInteropAuditLogs` runs them, and pins the *reason* each
invalid log is rejected rather than only the fact of it.

Canonical home: <https://github.com/did-method-plc/go-didplc/tree/main/testdata>, mirrored
into the method repository at
<https://github.com/did-method-plc/did-method-plc/tree/main/interop_tests/audit_log>.
Copied 2026-08-31. Dual-licensed MIT / Apache-2.0 by the did:plc authors, same as the
method repository.

## Why these are here as well as the golden fixtures

`../audit_atproto.json` and `../audit_legacy.json` are real histories captured from the
live registry: they prove this package accepts what the reference implementation actually
produced. They cannot cover a rejection, because the registry never accepted one — there is
no real DID whose log contains a nullification signed by an unauthorized key.

These vectors are the other half, and they are the reason to keep both: the suite caught a
signature encoding this package accepted and should not have (a trailing `\n`, which Go's
base64 decoder silently skips — see `sigEncoding` in operation.go).

## The valid logs, and what each one is for

| file                                    | what it pins                                                                                   |
|-----------------------------------------|------------------------------------------------------------------------------------------------|
| `log_bskyapp.json`                      | an ordinary long history                                                                       |
| `log_bnewbold_robocracy.json`           | another, with more key rotation                                                                |
| `log_legacy_dholms.json`                | a legacy `create` genesis, and the operation after it verified against the normalized key pair |
| `log_tombstone.json`                    | deactivation                                                                                   |
| `log_nullified_tombstone.json`          | a tombstone undone by a recovery                                                               |
| `log_nullification.json`                | the simple recovery                                                                            |
| `log_nullification_nontrivial.json`     | a recovery dropping more than one operation                                                    |
| `log_nullification_at_exactly_72h.json` | the window boundary: exactly 72h must be accepted, so the comparison is `>` and not `>=`       |
| `log_duplicate_rotation_keys.json`      | two byte-identical rotation keys                                                               |
| `log_empty_rotation_keys.json`          | an operation with `rotationKeys: []`, which nothing can ever follow                            |

The last two are load-bearing. Both hold states the specification forbids in a *new*
operation, and both must still replay — the registry applies its structural limits only to
incoming operations (`assertValidIncomingOp`, reached from `POST /:did` alone), never when
serving a stored log. They are what pins the read path open; see
`TestInteropPinsTheReadPathLenient` and "What this package trusts" in the package doc.

## Refreshing

```sh
cd controller/did-plc/testdata/interop
D=https://raw.githubusercontent.com/did-method-plc/go-didplc/main/testdata/audit_log
# add/remove files as the upstream suite changes
```

A new `invalid/` vector needs an entry in `interopReject` in interop_test.go naming the
error it must fail with; the test fails loudly if one is missing.
