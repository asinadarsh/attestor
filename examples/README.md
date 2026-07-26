# Example evidence packs

Two real packs from one recorded MCP session. They are identical except that
one byte was changed in the tampered copy. **You do not have to trust anything
in this repository to check them** — the anchor they both reference is in
Sigstore's public transparency log, which the author does not control.

| Pack | `attestor verify` |
|---|---|
| `pack-2026-07/` | `RESULT: VERIFIED` (exit 0) |
| `pack-2026-07-TAMPERED/` | `RESULT: TAMPER DETECTED at entry 5` (exit 1) |

The tampered copy has `payments.transfer 100.00` changed to `100000.00` —
one edit, no other differences. Diff them yourself:

```sh
diff <(jq -c . pack-2026-07/ledger/entries.jsonl) \
     <(jq -c . pack-2026-07-TAMPERED/ledger/entries.jsonl)
```

## Check the anchor against a log nobody here controls

```sh
# the anchor is public — this fetches it from Sigstore, not from this repo
curl -s https://rekor.sigstore.dev/api/v1/log/entries/108e9186e8c5677af836f886410e1a2e74e05afd82b8b93f5dcf7e88246e429a5ca690d5d65b9273 | jq .

# and it matches the copy stored in the pack, byte for byte
curl -s https://rekor.sigstore.dev/api/v1/log/entries/108e9186e8c5677af836f886410e1a2e74e05afd82b8b93f5dcf7e88246e429a5ca690d5d65b9273 | jq -r '.[].body' \
  | diff - <(jq -r .body pack-2026-07/anchors/rekor/*.json) && echo MATCH
```

Human-readable view: <https://search.sigstore.dev/?logIndex=2256661985>

`pack-2026-07/VERIFY.md` carries the full recipe, including verifying
Rekor's signature with `openssl` alone.

## What this does and does not prove

It proves the recorded history existed in this order no later than the
anchor's `integratedTime`, and that the tampered copy has been altered since.
It does not prove the recorder was told the truth — a compromised host can
attest lies faithfully. See the threat model in the root README.
