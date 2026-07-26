All research verified. Design document follows.

---

# Attestor — Ledger & Cryptography Design (MVP)

## 1. Record schema (one JSON object per line)

Every event is one JSONL line. Two zones: a **signed core** (covered by hash+sig) and **unsigned convenience fields** (strippable without breaking the chain).

**Signed core fields:**

| field | type | notes |
|---|---|---|
| `v` | int | schema version, `1` |
| `seq` | int | 0-based, strictly monotonic per ledger |
| `ts` | string | RFC 3339 UTC ms — *a claim by local clock, not trusted time* |
| `type` | string | `genesis` \| `session_start` \| `call_request` \| `call_result` \| `checkpoint` \| `anchor` \| `key_rotation` \| `session_end` |
| `session_id` | string | UUIDv7 |
| `call_id` | string | links request↔result; absent on non-call types |
| `actor` | object | `{agent, model, runtime}` strings |
| `tool` | object | `{server, name}` — MCP server + tool, or SDK provider+function |
| `salt` | string | 16 random bytes, hex, per entry |
| `payload_hash` | string | hex `SHA256(salt_bytes ‖ payload_bytes)` |
| `prev` | string | hex hash of previous entry; genesis uses `SHA256("attestor-genesis:"+ledger_id)` |
| `key_id` | string | first 16 hex of `SHA256(raw ed25519 pubkey)` |

**Unsigned fields:** `payload` (the raw wire JSON **as a string** — see §2), `hash` (hex SHA-256 of canonical core bytes), `sig` (base64 Ed25519 over the same canonical core bytes).

`call_request` is written *before* execution, `call_result` (with `status`, `duration_ms`) after — a crashed/hung tool call still leaves the attempt on record (flight-recorder semantics). `genesis` payload embeds the Ed25519 public key PEM + `ledger_id`, making the file self-describing; `key_rotation` payload is the new pubkey PEM, signed by the *old* key.

## 2. Canonical serialization: RFC 8785 JCS — but only for flat metadata

Pick **`canonicalize@3.0.0`** (RFC 8785 JCS). Justification vs `fast-json-stable-stringify`: JCS is an actual spec with cross-language implementations (Go/Rust/Python verifiers can be written without porting a library's quirks), which matters for "anyone can verify."

The known JCS attack surface (float re-serialization, lone surrogates, non-JSON types) is **eliminated structurally, not mitigated**: tool-call payloads are never canonicalized. The payload is captured as the exact wire bytes, stored as a JSON *string* field (strings round-trip byte-exactly through JSON), and bound via `payload_hash` over raw bytes. JCS only ever touches the core — flat strings and integers, no floats, no nesting beyond two levels. Verifier re-canonicalizes the parsed core; determinism is guaranteed because the input domain is trivial.

## 3. Hash chain

`entry.hash = SHA256(JCS(core))`, `core.prev = previous entry.hash`. SHA-256, full 64-hex, no truncation. Any edit/reorder/mid-delete breaks the chain at the tampered point; `seq` gaps make deletions independently obvious.

## 4. Signing: per-entry Ed25519, native `node:crypto`

**Per-entry signing** (not per-batch): Node 24 signs Ed25519 at >10k ops/s; agent tool calls are orders of magnitude rarer. Per-entry gives statement-level non-repudiation; batch signing saves nothing that matters here. `crypto.sign(null, canonicalCoreBytes, privKey)` / `crypto.verify(null, ...)` — sign the *bytes*, store `hash` merely as the chain link. **No @noble packages needed** — `node:crypto` has Ed25519 keygen/sign/verify and SHA-256 natively; adding noble would be a dependency for prestige.

**Keys:** `attestor keys init` → `crypto.generateKeyPairSync('ed25519')` → `~/.attestor/keys/<key_id>.pem` (PKCS#8, mode 0600) + `<key_id>.pub`. Optional passphrase → encrypted PKCS#8 (`aes-256-cbc` + scrypt, both native to `export({cipher, passphrase})`). **Rotation:** `attestor keys rotate` appends a `key_rotation` entry signed by the old key carrying the new pubkey; verify walks the rotation chain from genesis. MVP is manual rotation; no revocation list (see threat model).

## 5. Merkle checkpoints + Rekor anchoring

**Tree:** RFC 6962 construction exactly — leaves are entry hashes (all entries `[0, size)`), `leaf = SHA256(0x00 ‖ h)`, `node = SHAM256(0x01 ‖ L ‖ R)`, unbalanced trees per 6962 §2.1. Domain separation defeats leaf/node second-preimage confusion (the thing HN checks first on homemade Merkle code).

**Interval:** checkpoint on (64 entries ∨ 60 s since last unflushed entry ∨ session_end ∨ clean shutdown), whichever first. Checkpoint entry payload: `{ledger_id, tree_size, root}`.

**Anchoring — the trap I verified:** Rekor v1 **rejects Ed25519 with `hashedrekord`** ([rekor#851](https://github.com/sigstore/rekor/issues/851)) because pure Ed25519 cannot verify over a pre-hashed digest. Anyone who designs "Ed25519 + hashedrekord" ships a broken anchor. Fix: upload the **full signed checkpoint blob as a `rekord` entry** (Rekor verifies the sig over full content — Ed25519 works). Checkpoint blob is ~200 bytes of `{ledger_id, tree_size, root, ts, key_id}` — public exposure is a random UUID and a hash, zero PII. `POST https://rekor.sigstore.dev/api/v1/log/entries` via Node 24 global `fetch` (no client dep); persist the response (`uuid`, `logIndex`, `integratedTime`, `verification.signedEntryTimestamp`, inclusion proof) as an `anchor` entry referencing the checkpoint's `seq`. Rekor's `integratedTime` is the only **trusted** timestamp in the system.

**Rekor v1 vs v2:** the public instance still defaults to v1 and will get one year's freeze notice; v2 (tile-based, `log2025-1.rekor.sigstore.dev`) is GA but instance URLs rotate yearly ([Rekor evolution](https://blog.sigstore.dev/rekor-evolution/), [Rekor v2 GA](https://blog.sigstore.dev/rekor-v2-ga/)). MVP targets v1 REST; tag anchor records `{provider:"rekor-v1", url}` so a v2 writer is additive. Rate limits on the public instance: retry with backoff, queue anchors; a failed anchor widens the truncation window but never blocks recording.

## 6. Storage engine: append-only JSONL (SQLite rejected for MVP)

`~/.attestor/ledgers/<ledger_id>/ledger.jsonl`, single fd opened `O_APPEND`, `fsync` per entry (tool-call rates make this free; expose `--fsync=batch` knob later). Single-writer enforced by an `O_EXCL` pid lockfile — few lines, no dependency.

Why not `better-sqlite3@13.0.1`: (a) the evidence-pack story — a JSONL file **is** the exhibit; an auditor can eyeball it, `jq` it, and re-hash it with a 50-line script in any language, whereas a SQLite page file is an opaque binary whose B-tree mutates in place, muddying "append-only" claims even when logically true; (b) crash-safety is *simpler*, not worse: the only JSONL failure mode is a torn final line — on open, validate the tail; incomplete/hash-invalid last line is moved to `ledger.torn` and the chain resumes from the last good entry (a torn tail is indistinguishable from truncation-by-crash, which the anchor mechanism already brackets honestly); (c) MVP has no query workload — verify is a linear scan. Add a derived SQLite index later if ledgers hit GBs; it's a cache, never the source of truth.

## 7. Deterministic replay

The ledger is the replay format — no second format. `attestor replay <session_id>` filters entries by session, orders by `seq`, and emits `call_request`/`call_result` pairs; a replay harness substitutes recorded results for live execution (record-replay, VCR-style). `attestor export` emits an evidence bundle: `{entries[], checkpoints[], anchors[], pubkeys[]}` — self-contained for offline verification. Redacted entries replay as `[REDACTED payload_hash=…]` placeholders.

## 8. Threat model (put this table verbatim in the README — honesty is the HN defense)

| Attacker capability | Defeated by | Status |
|---|---|---|
| Edit any past entry | hash chain + per-entry sig breaks | ✅ in scope |
| Delete a middle entry | `prev` mismatch + `seq` gap | ✅ |
| Reorder entries | `prev` chain + `seq` | ✅ |
| Truncate tail (delete newest) | chain stays valid locally; signed checkpoint anchored in Rekor at size *N* proves the log was longer. **Window: entries since last anchor are silently truncatable** | ✅ post-anchor / ⚠️ ≤60 s window |
| Fork/rollback (show auditor an alternate history) | two Rekor entries under the same `ledger_id`+pubkey with inconsistent roots = cryptographic fork proof; `verify --deep` searches Rekor by pubkey and runs RFC 6962 consistency checks between anchored checkpoints | ✅ if verifier queries Rekor |
| Steal signing key (disk access) | cannot rewrite anchored history without Rekor collusion; **can** forge/fork from theft onward. Rotation bounds blast radius | ⚠️ partial — forward forgery out of scope |
| Root on host *during* recording | nothing — recorder signs what it saw; lies fed to it are faithfully attested | ❌ out of scope, say so |
| Delete entire ledger | Rekor entries under the pubkey survive as existence evidence; absence of a ledger proves nothing about activity | ⚠️ detection only |
| Compromise of Rekor itself | out of scope; Rekor's own witness/monitor ecosystem | ❌ out of scope |

## 9. Redaction: salted commitments, strippable by construction

Because the signed core binds `payload_hash = SHA256(salt ‖ payload)` and never the payload itself, redaction is `attestor redact <seq>`: delete the unsigned `payload` field, rewrite that line — chain, signatures, Merkle roots, and Rekor anchors all remain valid. The 16-byte random salt defeats dictionary/brute-force attacks on low-entropy redacted payloads (the reason plain `SHA256(payload)` would get shredded on HN). Holder of `(payload, salt)` can later prove content to an auditor selectively. `--hash-only` mode never writes payloads at all — PII never touches disk. This is commitment-based selective disclosure, not encryption; no key management for redaction.

## 10. Dependencies (versions verified against npm registry 2026-07-27)

- `canonicalize@3.0.0` — RFC 8785 JCS (runtime)
- `@sigstore/rekor-types@5.0.0` — TS types for Rekor v1 API (dev only)
- `node:crypto` + global `fetch` (Node 24) — Ed25519, SHA-256, scrypt, randomBytes, HTTP
- **Rejected:** `better-sqlite3@13.0.1` (§6); `sigstore@5.0.0` (Fulcio keyless flow — wrong model for a long-lived self-managed key); `@noble/curves@2.2.0`/`@noble/hashes@2.2.0` (redundant with node:crypto); `fast-json-stable-stringify@2.1.0` (not spec-backed)

## 11. HN tear-apart pre-mortem

1. **"Ed25519+hashedrekord is broken"** → already routed around via `rekord` type; cite rekor#851 in docs. Shipping the broken combo is the #1 credibility killer.
2. **"JCS float canonicalization bugs"** → structurally excluded: payloads hashed as raw bytes, JCS restricted to flat string/int core (§2). State this.
3. **"Key sits next to the ledger — tamper-evidence theater"** → never claim tamper-*proof*. Claim: evidence integrity against *post-hoc* modification and against parties without the key; anchored history survives even key theft. HSM/TPM/KMS = roadmap, not MVP.
4. **"Self-reported timestamps"** → docs must say entry `ts` is a claim; Rekor `integratedTime` is the trust anchor.
5. **"Homemade Merkle"** → RFC 6962 byte-for-byte, with domain-separation prefixes, plus consistency proofs between own checkpoints in `verify --deep`. Test vectors against CT test data.
6. **Vocabulary** → "tamper-evident," never "immutable"/"blockchain." The 60 s truncation window is disclosed, not buried.

Sources: [rekor#851](https://github.com/sigstore/rekor/issues/851), [Rekor evolution blog](https://blog.sigstore.dev/rekor-evolution/), [Rekor v2 GA](https://blog.sigstore.dev/rekor-v2-ga/), [rekor-tiles](https://github.com/sigstore/rekor-tiles), [Rekor types](https://github.com/sigstore/rekor/blob/main/types.md), [Chainguard sign+upload guide](https://edu.chainguard.dev/open-source/sigstore/rekor/how-to-sign-and-upload-metadata-to-rekor/), [sigstore-js](https://github.com/sigstore/sigstore-js), npm registry via `npm view` (versions in §10).