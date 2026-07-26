# Verifying this evidence pack

## Option A — attestor CLI (30 seconds)

```sh
npx attestor verify .            # offline: chain, Merkle roots, signatures, stored anchors
npx attestor verify . --online   # also compares every anchor against the public Rekor log
```

Exit codes: 0 verified · 1 tamper · 2 usage/IO error · 3 Rekor unreachable.

## Option B — no attestor, no trust in our code (curl + jq + openssl)

Every checkpoint of this ledger was anchored in Sigstore's public Rekor
transparency log. You can confirm the anchors are real, public, and signed by
Rekor without running anything we shipped.

### 1. The anchor exists in the public log

```sh
curl -s "https://rekor.sigstore.dev/api/v1/log/entries/108e9186e8c5677af836f886410e1a2e74e05afd82b8b93f5dcf7e88246e429a5ca690d5d65b9273" | jq .
# → the same entry stored in anchors/rekor/11.json
# → human view: https://search.sigstore.dev/?logIndex=2256661985
```

### 2. The stored copy matches the public log byte-for-byte

```sh
curl -s "https://rekor.sigstore.dev/api/v1/log/entries/108e9186e8c5677af836f886410e1a2e74e05afd82b8b93f5dcf7e88246e429a5ca690d5d65b9273" \
  | jq -r '.[].body' > /tmp/public-body.b64
jq -r '.body' "anchors/rekor/11.json" | diff - /tmp/public-body.b64 && echo MATCH
```

### 3. Rekor's signature (SET) over the stored entry verifies

Rekor signs the JSON-canonicalized `{body, integratedTime, logID, logIndex}`.
For these flat ASCII fields, `jq -cS` produces exactly that canonical form.
The pinned log key is in `keys/rekor-pub.pem`; cross-check it first:

```sh
curl -s "https://rekor.sigstore.dev/api/v1/log/publicKey" | diff - keys/rekor-pub.pem && echo KEY-MATCHES-PUBLIC-LOG
A="anchors/rekor/11.json"
jq -cjS '{body, integratedTime, logID, logIndex}' "$A" > /tmp/set-bundle.json
jq -r '.verification.signedEntryTimestamp' "$A" | base64 -d > /tmp/set.sig
openssl dgst -sha256 -verify keys/rekor-pub.pem -signature /tmp/set.sig /tmp/set-bundle.json
# → Verified OK
```

### 4. What the anchor commits to

The anchored artifact is the SHA-256 of a checkpoint entry's canonical signed
core (RFC 8785 JCS). That checkpoint commits an RFC 6962 Merkle root over
every ledger entry before it — so any edit to `ledger/entries.jsonl` at or
before seq 11 changes hashes that Rekor has already
publicly timestamped. Decode it yourself:

```sh
jq -r '.body' "$A" | base64 -d | jq .   # → kind hashedrekord, spec.data.hash = anchored digest
```

## What this proves — and what it does not

- **Proves**: the recorded history existed, in this order, no later than each
  anchor's `integratedTime`; any post-hoc edit, reorder, deletion, or
  truncation at-or-before an anchored checkpoint is detectable by anyone.
- **Does not prove**: that the recorder was fed the truth (a compromised host
  during recording can attest lies faithfully), or anything about entries
  after the last anchor (window ≤ 64 entries / 60 s by default, reported as
  ANCHOR LAG). Entry `ts` fields are local-clock claims; Rekor
  `integratedTime` is the trusted time.
- Ledger entries: 13. Independent re-implementation targets:
  RFC 8785 (JCS), RFC 6962 §2.1 (Merkle), ECDSA P-256 + SHA-256 (signatures).
