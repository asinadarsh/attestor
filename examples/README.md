# Example evidence packs

Two real packs from one recorded MCP session. They are identical except that
one byte was changed in the tampered copy. **You do not have to trust anything
in this repository to check them** — the anchor they both reference is in
Sigstore's public transparency log, which the author does not control.

| Pack | offline | `--online` |
|---|---|---|
| `pack-2026-07/` | exit 4 — chain intact, anchor unconfirmed | exit 0 — VERIFIED |
| `pack-2026-07-TAMPERED/` | exit 1 — TAMPER at entry 5 | exit 1 |

```sh
npx attestor verify pack-2026-07            # 4: honest — see below
npx attestor verify pack-2026-07 --online   # 0: anchor authenticated against the public log
npx attestor verify pack-2026-07-TAMPERED   # 1: caught
```

## Why the clean pack exits 4 offline, and why that is the point

The pack ships a copy of Sigstore's log public key. That copy cannot be used to
authenticate the pack: an attacker who forged the anchors would ship a matching
key, and everything would look consistent. So verifying offline on a machine
that has never pinned the log key reports exit 4 — *the hash chain and
signatures are intact, but whether the anchor is genuinely in the public log is
unconfirmed*. Exit 0 requires a key you trust independently: `--online` fetches
it live, or you can pin one at `~/.attestor/keys/rekor-pub.pem`.

A tool that printed VERIFIED here would be lying by omission.

## Check the anchor against a log nobody here controls

```sh
# fetched from Sigstore, not from this repo
curl -s https://rekor.sigstore.dev/api/v1/log/entries/108e9186e8c5677aa3ee87c0ef6bf1bc317e4a557f97f298ede6c85454e1e60819c77389dab1b3ad | jq .

# and it matches the copy stored in the pack, byte for byte
curl -s https://rekor.sigstore.dev/api/v1/log/entries/108e9186e8c5677aa3ee87c0ef6bf1bc317e4a557f97f298ede6c85454e1e60819c77389dab1b3ad | jq -r '.[].body' \
  | diff - <(jq -r .body pack-2026-07/anchors/rekor/*.json) && echo MATCH
```

Human-readable view: <https://search.sigstore.dev/?logIndex=2256753011>

`pack-2026-07/VERIFY.md` carries the full recipe, including verifying Rekor's
signature with `openssl` alone.

## The difference between the two packs

```sh
diff <(jq -c . pack-2026-07/ledger/entries.jsonl) \
     <(jq -c . pack-2026-07-TAMPERED/ledger/entries.jsonl)
```

One field: `payments.transfer 100.00` became `100000.00`.

## What this proves — and what it does not

It proves the recorded history existed in this order no later than the anchor's
`integratedTime`, and that the tampered copy has been altered since. It does
not prove the recorder was told the truth — a compromised host can attest lies
faithfully. See the threat model in the root README.
