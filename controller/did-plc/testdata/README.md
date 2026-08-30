# did:plc test fixtures

Verbatim responses captured from the live registry at <https://plc.directory> on
**2026-08-28**. They are the ground truth this package is tested against: every CID and
every signature in them was produced by the reference implementation
([did-method-plc](https://github.com/did-method-plc/did-method-plc)), so recomputing the
CIDs, re-deriving the DID from the genesis operation and re-verifying the signatures
checks our DAG-CBOR encoder, CID derivation and validation rules against it rather than
against itself.

They are public records from a public directory; the operation log of a did:plc DID is
append-only and readable by anyone.

## Files

| file | endpoint | contents |
|---|---|---|
| `audit_atproto.json` | `GET /:did/log/audit` | 3 entries, all `plc_operation`, none nullified |
| `audit_legacy.json` | `GET /:did/log/audit` | 6 entries: a legacy `create` genesis followed by 5 `plc_operation` |

Two DIDs, chosen for what they cover:

- **`did:plc:ewvi7nxzyoun6zhxrhs64oiz`** (`atproto.com`) — the current operation format.
  Only its `/log/audit` response is kept: that is the only history this package reads, and
  the canonical `/log` view is derived from it by dropping the nullified entries.
- **`did:plc:ragtjsm2j2vknwkz3zp4oxrd`** (`paul.bsky.social`) — registered in November 2022,
  when the genesis operation still used the legacy `create` format. It is the fixture that
  covers normalizing such an operation (its recovery key and signing key become two
  rotation keys, in that order) *and* the rule that the operation after it is verified
  against that normalized pair. Found with `GET /export?count=30`, which returns the
  earliest operations the directory holds.

## Refreshing

```sh
cd controller/did-plc/testdata
D=did:plc:ewvi7nxzyoun6zhxrhs64oiz
curl -s "https://plc.directory/$D/log/audit" | python3 -m json.tool > audit_atproto.json

D=did:plc:ragtjsm2j2vknwkz3zp4oxrd
curl -s "https://plc.directory/$D/log/audit" | python3 -m json.tool > audit_legacy.json
```

These are pinned snapshots of live, still-mutable DIDs: if either subject submits another
operation, a refresh picks it up. The entry counts are asserted in
`TestGoldenAuditLogsFromTheLiveRegistry`, and `TestTamperedCidIsDetected` names the last
CID of `audit_atproto.json` literally, so both need updating alongside a refresh.

The files are pretty-printed only for readability. Nothing is hashed from the JSON — the
CIDs come from the DAG-CBOR re-encoding of the parsed operations — so reformatting them is
harmless, but editing any field is not: it will fail validation, which is the point of
`TestTamperedCidIsDetected` and `TestNullifiedFlagsMustMatchTheReplay`.
