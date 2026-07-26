All research verified live. Design document follows.

---

# ATTESTOR — Rekor Anchoring, Verify CLI, Evidence Packs, Tamper Demo (design doc)

## 1. Verified Rekor facts (live-checked 2026-07-27)

- **Rekor v1** (`https://rekor.sigstore.dev`) is up and accepting writes. Active shard treeID `1193050959916656506`, treeSize ~2.134B (confirmed via `GET /api/v1/log`). No auth, no API key. Rate limits exist (Cloud Armor at the LB) but are undocumented — design for HTTP 429/5xx with backoff, don't assume a number.
- **Write**: `POST /api/v1/log/entries`, body `{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{...}}`. `hashedrekord` v0.0.1 schema (confirmed from repo): `spec.data.hash = {algorithm: "sha256"|"sha384"|"sha512", value: <lowercase hex>}`, `spec.signature = {content: <b64 raw sig>, publicKey: {content: <b64 PEM>}}`. Returns **201** with `{<entryUUID>: entry}` map + `Location` header; **409** on duplicate (follow `Location` to fetch existing entry).
- **Read** (confirmed by fetching a live entry): `GET /api/v1/log/entries?logIndex=N` or `/api/v1/log/entries/{uuid}` returns `{uuid: {body(b64), integratedTime, logID, logIndex, verification: {signedEntryTimestamp, inclusionProof: {checkpoint, hashes[], logIndex, rootHash, treeSize}}}}`. Inclusion proof comes **free with entry retrieval** — no separate proof endpoint needed. Rekor's log pubkey: `GET /api/v1/log/publicKey`.
- **Rekor v2 (rekor-tiles)**: GA since 2025-10-10. Public instance `https://log2025-1.rekor.sigstore.dev`, single write endpoint `POST /api/v2/log/entries`, tile-based reads, only `hashedrekord` + `dsse` types. Sigstore **explicitly warns against hardcoding** the log2025-1 URL (a 2026 instance will replace it; URL distributed via TUF SigningConfig). v1 stays writable with ≥1yr freeze notice.
  **Decision: ship on v1**, make base URL configurable (`ATTESTOR_REKOR_URL`). v1 is stable, REST, unauthenticated, and won't freeze without a year's notice. Add v2 as a follow-up once its URL is TUF-stable; our anchor payload (a 32-byte digest) is identical in both.
- **npm**: `sigstore@5.0.0`, `@sigstore/sign@5.0.0`, `@sigstore/rekor-types@5.0.0` (latest). **Decision: plain `fetch` (Node 24 global), zero runtime deps.** sigstore-js is built around keyless Fulcio/OIDC bundle signing ("code-signing for npm packages") and drags in make-fetch-happen etc.; our flow is self-managed keys + hashedrekord = ~60 lines of fetch. Use `@sigstore/rekor-types` as a **devDependency** for TS types only. Zero-dep verify CLI is itself the HN pitch: auditable in one sitting.
- **Crypto gotcha (flagged, test day 1)**: `hashedrekord` verifies the signature against the *digest*, which pure Ed25519 cannot do — Rekor v1 rejects Ed25519 for hashedrekord (cosign uses ECDSA here for the same reason). **Use ECDSA P-256 + SHA-256** (`node:crypto` `generateKeyPairSync('ec', {namedCurve:'prime256v1'})`) for the recorder key. Works in v1 and v2, matches cosign convention.

## 2. Anchoring flow

Ledger entries are single-line JSON in append-only JSONL; `entry.hash = sha256(exact line bytes minus hash field)` — hash the bytes as written, **no canonicalization scheme needed** (skipped RFC 8785 JCS; add only if entries ever get re-serialized).

**Checkpoint** (every N=100 entries or 5 min idle or explicit `flush`, whichever first):
1. Build RFC 6962 Merkle tree over **all entry hashes from genesis** (leaf = `sha256(0x00‖h)`, node = `sha256(0x01‖L‖R)`). Full-history tree keeps single-entry proofs simple against the latest checkpoint; O(n) rebuild is fine at MVP scale. `// ponytail: full rebuild per checkpoint; incremental tree if ledgers exceed ~1M entries`
2. Checkpoint record (one canonical line): `{seq_range, tree_size, root_hash, prev_checkpoint_hash, ts, key_fingerprint}` → sign bytes with recorder P-256 key → append to `checkpoints.jsonl`.
3. **Anchor**: `artifactBytes` = the signed checkpoint line. POST hashedrekord: `data.hash = {sha256, hex(sha256(artifactBytes))}`, `signature.content` = b64(DER ECDSA sig over artifactBytes), `publicKey.content` = b64(PEM pubkey).
4. On 201/409: store the **full returned entry** (uuid, logIndex, logID, integratedTime, SET, inclusionProof) as `anchors/<checkpoint_seq>.json`, and append an `anchor` record to the ledger referencing it — so anchoring itself is in the chain.

**Offline queue**: anchoring never blocks recording. Failed submits append to `anchors/pending.jsonl`; retry on process start, on every new checkpoint, and on a 60s timer — exponential backoff 1m→2m→…→1h cap, jittered, per-checkpoint. Honesty rule: `verify` reports the **anchor lag** — entries after the last anchored checkpoint are chain-protected but not yet externally anchored; never imply otherwise.

Also pin `GET /api/v1/log/publicKey` (Rekor's log key) at first anchor into `keys/rekor-pub.pem` for offline SET verification.

## 3. `attestor verify` CLI

```
attestor verify <dir> [--entry SEQ] [--online] [--json]
```

**Checks, in order (each prints one line):**
1. `CHAIN` — recompute every entry hash; verify `prev_hash` links, no gaps in seq.
2. `MERKLE` — for each checkpoint, rebuild tree at its `tree_size`; root must equal `root_hash`; checkpoints chain via `prev_checkpoint_hash`.
3. `SIG` — every checkpoint signature verifies against the recorder pubkey (fingerprint printed).
4. `ANCHOR` (offline, per anchored checkpoint):
   a. decode stored Rekor `body` → hashedrekord; `data.hash.value == sha256(checkpoint line)`;
   b. verify SET: Rekor log key over canonicalized `{body, integratedTime, logID, logIndex}`;
   c. recompute the RFC 6962 audit path from the entry leaf hash through `inclusionProof.hashes` → must equal `inclusionProof.rootHash`; verify the signed note in `inclusionProof.checkpoint` against the Rekor key.
5. `ANCHOR-ONLINE` (`--online` only) — `GET /api/v1/log/entries/{uuid}`, byte-compare `body`, verify a **fresh** inclusion proof. This is what defeats full-ledger-rewrite attacks.

**PASS output:**
```
✔ CHAIN    1,204 entries, hash chain intact
✔ MERKLE   12 checkpoints, all roots reproduce
✔ SIG      12/12 checkpoint signatures valid (key SHA256:xK3f…)
✔ ANCHOR   12/12 anchored in Rekor (log 1193…506, latest logIndex 2134102211)
ℹ ANCHOR LAG  4 entries (seq 1201–1204) after last anchor — chain-protected, not yet anchored
RESULT: VERIFIED  (exit 0)
```
**Tamper output:**
```
✖ CHAIN    TAMPER DETECTED at entry 7
           expected hash 4be1…90a2, got e77c…01dd
           field diff: tool_args.amount "100.00" → "100000.00"
           blast radius: entries 7–1204 untrustworthy
✖ MERKLE   checkpoint #1 root mismatch
✔ ANCHOR   checkpoint #1 immortalized in Rekor logIndex 213400xxxx
           → https://search.sigstore.dev/?logIndex=213400xxxx
RESULT: TAMPER DETECTED  (exit 1)
```
**Exit codes**: `0` verified · `1` tamper/verification failure · `2` usage/IO error · `3` `--online` requested but Rekor unreachable (CI can distinguish network from tamper). `--entry SEQ` runs checks 1,4 scoped: entry hash + inclusion path to nearest covering checkpoint.

## 4. Evidence pack (`attestor export`)

```
attestor-pack-2026-07-27T09-00Z/
  manifest.json        # pack version, attestor version, time range, entry count,
                       # key fingerprints, rekor logID, sha256 of every pack file
  ledger/entries.jsonl
  ledger/checkpoints.jsonl
  anchors/rekor/*.json # full entries: body, SET, inclusion proofs
  keys/recorder-pub.pem
  keys/rekor-pub.pem
  controls/mapping.json
  report.html          # self-contained: timeline, verify result, control table
  VERIFY.md            # `npx attestor verify .` + a pure curl/openssl recipe
```
`VERIFY.md` matters for HN: independent verification without trusting our binary.

**Honest control mappings** (`mapping.json` claims *supports evidence for*, never *makes you compliant* — top-of-file disclaimer: "Attestor provides audit-trail evidence. Compliance determinations are made by your assessor."):
- **SOC 2 (2017 TSC)**: **CC7.2** (monitoring system components for anomalous activity — complete record of agent actions), **CC7.3** (evaluation of security events — verifiable reconstruction of what an agent did), **CC4.1** (ongoing evaluations of internal control — independently re-runnable verification). If Processing Integrity in scope: **PI1.4/PI1.5** (complete, accurate, timely retention of outputs/records).
- **EU AI Act, Art. 12** (record-keeping for high-risk systems): **12(1)** — "technically allow for the automatic recording of events (logs)" over the system lifetime: directly supported, with tamper-evidence exceeding the bar. **12(2)(a)** — recording the period of each use (timestamps per call). Plus **Art. 19** (providers keep Art. 12 logs) and **Art. 26(6)** (deployers retain logs ≥6 months) — retention with integrity proof. Do **not** claim 12(2)(b–d) (reference-DB checks, input-data logging, human-verifier identity) unless the SDK user actually records those fields; mapping.json marks them "conditional — populated only if recorded."
- **HIPAA Security Rule**: **45 CFR §164.312(b)** Audit controls (record and examine activity in systems containing ePHI), **§164.308(a)(1)(ii)(D)** Information system activity review, **§164.312(c)(1)** Integrity — applied to the audit trail itself (tamper-evident logs). Never say "HIPAA certified" (no such certification exists).

## 5. `attestor demo tamper` (scripted, ~30s)

1. Temp dir; record 12 synthetic tool calls (real keys, real hashes — one is `payments.transfer {amount: "100.00"}`); checkpoint; anchor to real Rekor (fallback `--offline` prints "simulated anchor" honestly); run verify → full green PASS block.
2. Print `--- attacker edits the ledger ---`; byte-edit entry 7's amount to `100000.00` in place, show the diff.
3. Run verify → TAMPER DETECTED block (above), exit 1, plus `audit-packet.json` (finding, blast radius, Rekor URL) printed to stdout.
4. Print the kicker narrative: *"To hide this, the attacker must rewrite entries 7–12, re-sign the checkpoint (needs your private key), AND replace the anchor — but the original root is already public at search.sigstore.dev logIndex N. Rekor is append-only; `verify --online` compares against the public log."* Then actually run `verify --online` against the fully-rewritten-and-resigned variant to demonstrate the catch.

## 6. Show HN pitch (README opener)

**Show HN: Attestor — a tamper-evident flight recorder for AI agents.** Your agents are calling tools that move money and touch PHI; when a regulator or incident review asks "what exactly did the agent do," a mutable app log is not an answer. Attestor records every tool call into a hash-chained ledger, checkpoints it with Merkle roots, and anchors each root in Sigstore's public Rekor transparency log — so tampering with any recorded call breaks verification loudly, and even rewriting the whole ledger with stolen keys can't beat the public log. Zero-dependency `attestor verify` CLI anyone can run, plain-curl verification recipe included, one-command evidence packs mapped (honestly — evidence, not certification) to SOC 2 CC7.2/CC7.3, EU AI Act Art. 12, and HIPAA §164.312(b). Try `npx attestor demo tamper`.

## Open flags for synthesis agent

1. Ed25519-hashedrekord incompatibility is high-confidence but **verify with one live POST before committing key format** (affects SDK + proxy keygen — coordinate).
2. SET verification canonicalization (check 4b) is the fiddliest code (~40 lines); Rekor signs the JSON-canonicalized entry — test against the live entry fetched above.
3. Rekor v1 freeze: watch for the deprecation announcement; v2 migration is a URL + endpoint swap, same digest payload.

Sources: [Rekor v2 GA — Sigstore Blog](https://blog.sigstore.dev/rekor-v2-ga/) · [sigstore/rekor](https://github.com/sigstore/rekor) · [sigstore/rekor-tiles CLIENTS.md](https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md) · [Rekor overview — docs.sigstore.dev](https://docs.sigstore.dev/logging/overview/) · [rekor-tiles rate-limit issue #355](https://github.com/sigstore/rekor-tiles/issues/355) · live API responses from rekor.sigstore.dev · npm registry (`sigstore@5.0.0`, `@sigstore/rekor-types@5.0.0`).