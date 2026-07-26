# Attestor — Synthesis Blueprint (final)

## Conflict resolutions (decisions, with winners)

| # | Conflict | Decision | Why |
|---|---|---|---|
| 1 | Signing key: Ed25519 + Rekor `rekord` full-blob (crypto doc) vs ECDSA P-256 + `hashedrekord` (anchor doc) | **ECDSA P-256 (`prime256v1`) + `hashedrekord`, one key for entries AND checkpoints** | Rekor v2 supports only `hashedrekord`+`dsse` — the `rekord` type strands us on v1. Ed25519+hashedrekord is rejected (rekor#851). P-256 works on v1 and v2, matches cosign convention, native in `node:crypto`. Single key = single rotation story. |
| 2 | Canonicalization: JCS flat core + raw-byte payload_hash (crypto doc) vs "hash exact line bytes, no canonicalization" (anchor/integration docs) | **JCS core + salted raw-byte `payload_hash`** | Redaction rewrites lines (drops unsigned `payload`) — byte-hashing whole lines breaks redaction structurally. JCS restricted to flat strings/ints keeps the crypto-doc safety argument; wire bytes are still committed exactly via `payload_hash` = SHA256(salt‖bytes), so the integration doc's "no canonicalization dispute on the payload" property is preserved. |
| 3 | Checkpoint cadence: 64 entries/60 s vs 100/5 min | **64 entries ∨ 60 s idle ∨ session_end ∨ clean shutdown** | Smaller disclosed truncation window; cost is negligible. |
| 4 | Checkpoint storage: in-chain entries vs separate `checkpoints.jsonl` | **In-chain `checkpoint` and `anchor` entry types**; bulky full Rekor responses in `anchors/<seq>.json`, referenced by the anchor entry | One chain covers everything; the ledger file stays the single exhibit. |
| 5 | Durability default: fsync-per-entry vs group commit | **`strict` (fsync per entry) default; `--durability group` (25 ms/256) opt-in** | Fail-closed philosophy (block-mode default) demands the record survive the crash that caused the block. Tool-call rates make it free. |
| 6 | Packaging: `@attestor/sdk` scope vs single package | **One published package `attestor`** with `bin: attestor` and subpath export `attestor/sdk` | `npx attestor demo tamper` needs the bare name; one package.json, one publish. |
| 7 | "Zero-dep" pitch vs `canonicalize` | **Keep `canonicalize@3.0.0` as the sole runtime dep** | It is effectively the RFC 8785 reference implementation; a homemade canonicalizer is the worse HN look. Pitch: "one runtime dependency — the JCS spec implementation." |

Failure mode `--on-error block` default, gap markers in `continue` mode, stdio-only proxy, Rekor v1 with configurable URL, JSONL over SQLite, full-tree rebuild per checkpoint (`// ponytail: O(n) rebuild; incremental tree at ~1M entries`): all three docs agree or don't conflict — adopted as written.

## 1. Monorepo layout (npm workspaces)

```
~/attestor/
  package.json                 # private, workspaces: ["packages/*"]
  README.md                    # threat-model table verbatim (crypto doc §8) + Show HN opener (anchor doc §6)
  packages/attestor/           # published as "attestor"
    package.json               # bin.attestor, exports: ".", "./sdk"; type: module
    src/cli.ts                 # node:util parseArgs; subcommands: keys, wrap, install, verify, export, redact, replay, demo
    src/ledger.ts              # append/O_APPEND+lockfile, JCS core, hash chain, sign, torn-tail recovery
    src/keys.ts                # P-256 keygen/load/rotate, key_id
    src/merkle.ts              # RFC 6962 tree + inclusion/consistency proofs
    src/checkpoint.ts          # cadence + checkpoint entries
    src/rekor.ts               # hashedrekord POST/GET via fetch, pending queue+backoff, SET verify
    src/verify.ts              # CHAIN/MERKLE/SIG/ANCHOR/ANCHOR-ONLINE, exit codes 0/1/2/3
    src/proxy.ts               # stdio byte relay + tap + async writer
    src/sdk.ts                 # Attestor class: wrapFetch(), record()
    src/export.ts  src/redact.ts  src/demo.ts
    test/*.test.ts             # node:test, run via Node 24 native type stripping
    test/vectors/              # CT/RFC6962 known answers; captured live Rekor entry fixture
  packages/toy-mcp-server/     # private; ~60-line stdio MCP server (one echo tool) for tests + demo
```

## 2. Ledger record schema + crypto (final)

Path: `$ATTESTOR_HOME/ledgers/<ledger_id>/ledger.jsonl`, one JSON object per line, single-writer pid lockfile.

**Signed core** (covered by hash+sig): `v:1`, `seq` (0-based monotonic), `ts` (RFC 3339 UTC ms — documented as a *claim*), `type`, `session_id` (UUIDv7), `call_id?`, `direction?` (`c2s|s2c`, proxy entries), `origin` (`proxy|sdk|manual|system`), `actor?` `{agent,model,runtime}`, `tool?` `{server,name}`, `salt` (16 random bytes hex), `payload_hash` = hex SHA256(salt_bytes‖payload_bytes), `prev` (previous entry hash; genesis: SHA256(`"attestor-genesis:"+ledger_id`)), `key_id` (first 16 hex of SHA256(SPKI DER pubkey)).

**Types**: `genesis` (embeds pubkey PEM + ledger_id — self-describing), `session_start` (integration doc §6 metadata; env deliberately excluded), `wire` (any relayed MCP line that isn't a tools/call pair), `call_request` (written *before* execution), `call_result` (`status`, `duration_ms`), `tool_execution` (SDK `record()`), `checkpoint` `{ledger_id, tree_size, root}`, `anchor` `{checkpoint_seq, provider:"rekor-v1", uuid, logIndex, integratedTime, url}`, `gap`, `key_rotation` (new pubkey signed by old key), `session_end`.

**Unsigned**: `payload` (exact wire/body bytes **as a JSON string** — strippable), `hash` (hex SHA256(JCS(core))), `sig` (base64 DER ECDSA-P256-SHA256 over the same JCS core bytes, `crypto.sign('sha256', …)`).

**Merkle**: RFC 6962 exactly — `leaf = SHA256(0x00‖entry.hash_bytes)`, `node = SHA256(0x01‖L‖R)`, unbalanced per §2.1, full-history tree over `[0, tree_size)`.

**Anchoring**: artifact = the checkpoint entry's JCS core bytes. POST `{apiVersion:"0.0.1", kind:"hashedrekord", spec:{data:{hash:{algorithm:"sha256", value:hex}}, signature:{content:b64(DER sig), publicKey:{content:b64(PEM)}}}}` to `$ATTESTOR_REKOR_URL/api/v1/log/entries`; 201/409→store full entry in `anchors/`, append `anchor` entry. Pin Rekor log pubkey to `keys/rekor-pub.pem` at first anchor. Anchoring never blocks recording; `anchors/pending.jsonl` with jittered backoff 1 m→1 h.

**Redaction**: `attestor redact <seq>` deletes unsigned `payload`; chain/sigs/roots/anchors stay valid (salted commitment defeats brute-force). `--hash-only` mode never writes payloads.

**Keys**: `attestor keys init` → `generateKeyPairSync('ec',{namedCurve:'prime256v1'})` → PKCS#8 at `~/.attestor/keys/<key_id>.pem` (0600), optional scrypt-encrypted. Manual rotation via `key_rotation` entry; no revocation (disclosed).

## 3. Components, build order, size

| # | Component | Depends on | ~LoC |
|---|---|---|---|
| 0 | **Day-1 spike**: live POST of P-256+hashedrekord to rekor.sigstore.dev, capture response as test fixture | — | 30 (throwaway) |
| 1 | Ledger core + keys | — | 450 |
| 2 | Merkle + checkpoint | 1 | 250 |
| 3 | `verify` (offline checks 1–4) | 1,2 | 350 |
| 4 | Rekor anchor + `verify --online` + SET verify | 2,3 | 300 |
| 5 | MCP stdio proxy (`wrap`, `install`) | 1 | 250 |
| 6 | SDK (`wrapFetch`, `record`) | 1 | 250 |
| 7 | Evidence pack (`export`) | 1–4 | 300 |
| 8 | `redact`, `replay`, `demo tamper` | all | 250 |

~2.4 k LoC total. Spike #0 is mandatory before committing key format (anchor doc's open flag #1).

## 4. Dependencies (verified against npm 2026-07-27)

**Runtime**: `canonicalize@3.0.0`. Nothing else — `node:crypto`, `node:child_process`, global `fetch`, `node:util` parseArgs cover the rest.
**Dev**: `typescript@7.0.2` (d.ts emit + typecheck; fall back to `^5.9` if TS7 emit misbehaves — one-line change), `@types/node@^24`, `@modelcontextprotocol/sdk@1.29.0`, `@anthropic-ai/sdk@0.115.0`, `openai@6.49.0`, `@sigstore/rekor-types@5.0.0`. Tests run on `node:test` with Node 24 native type stripping — no tsx, no vitest.
**Rejected**: `better-sqlite3`, `sigstore`/`@sigstore/sign` (Fulcio keyless — wrong model), `@noble/*`, `fast-json-stable-stringify`, `cross-spawn` (revisit only if Windows support is demanded).

## 5. Config surface

Env: `ATTESTOR_HOME` (default `~/.attestor`), `ATTESTOR_REKOR_URL` (default `https://rekor.sigstore.dev`), `ATTESTOR_OFFLINE=1` (queue anchors, never POST), `ATTESTOR_LIVE=1` (opt-in live Rekor tests).
Flags: `--ledger <dir>`, `--on-error block|continue` (default block), `--durability strict|group` (default strict), `--hash-only`, `--offline`, `--online`, `--json`, `--entry <seq>`, `--passphrase-file`.
No `attestor.config` file for MVP — flags+env cover everything; add a file when someone has >3 flags in every invocation.

## 6. Test plan (automated, `node:test`)

- **Chain verify round-trip**: append N entries → verify passes; seq monotonicity; lockfile excludes second writer; torn-tail: truncate mid-line → recovery to `ledger.torn`, chain resumes, verify passes with warning.
- **Tamper matrix** (each must exit 1 with correct blast radius): mutate a core field; mutate unsigned payload (payload_hash mismatch); delete middle line; swap two lines; truncate tail post-anchor (offline: anchor-lag info; with stored anchor: MERKLE fail); re-sign entry with a different key (key_id/rotation-chain fail); redacted entry still verifies (must pass).
- **Merkle**: RFC 6962 known-answer vectors (CT test data) for roots at sizes 1–8; inclusion proofs for every leaf; consistency proofs between successive checkpoints; odd/unbalanced sizes.
- **JCS core**: key-order, non-ASCII strings, stability across parse→re-canonicalize.
- **Proxy round-trip**: real `@modelcontextprotocol/sdk` Client + `StdioClientTransport` pointing at `attestor wrap -- node toy-mcp-server`: initialize/tools/list/tools/call succeed byte-identically; notifications pass through; unparsable line relayed + recorded as `wire`/unparsed; child exit code propagated; block mode: unwritable ledger → synthesized `-32000` JSON-RPC error, no hang; continue mode → gap marker appended on recovery.
- **SDK**: `wrapFetch` against a stub fetch returning an Anthropic `tool_use` body and OpenAI `tool_calls` body → correct extraction + linkage via `record()`; SSE stream tee reconstructs `input_json_delta` while app-side stream is unaffected.
- **Rekor mock** (`node:http`): asserts exact hashedrekord body shape; 201 and 409+Location paths; pending-queue retry/backoff; SET verification against the captured live-entry fixture from spike #0. One opt-in live smoke test (`ATTESTOR_LIVE=1`).
- **Demo e2e**: `attestor demo tamper --offline` asserts green run exit 0, tampered run exit 1.

## 7. Demo script (`attestor demo tamper`, ~30 s)

1. Temp ledger, real keygen; record 12 synthetic tool calls (one `payments.transfer {"amount":"100.00"}`); checkpoint; anchor to real Rekor (`--offline` prints "simulated anchor" honestly); run verify → full green PASS block (anchor doc §3 format, incl. ANCHOR LAG line).
2. Print `--- attacker edits the ledger ---`; byte-edit entry 7 to `100000.00`; show diff.
3. verify → `TAMPER DETECTED at entry 7`, field diff, blast radius 7–12, Rekor search.sigstore.dev link, `audit-packet.json` to stdout, exit 1.
4. Kicker: rewrite+re-sign the whole ledger with the (attacker-held) key, then run `verify --online` → caught against the public log. Narration printed verbatim per anchor doc §5.4.

## 8. Open risks / honest cut-lines

1. **SET verification** (~40 fiddliest lines): cut-line — ship offline inclusion-proof check + `--online` fresh-proof compare; mark SET verify experimental if it slips. `--online` already defeats full-rewrite.
2. **SDK streaming tee**: cut-line — non-streaming responses first; streaming reconstruction second. Disclosed if cut.
3. **HTTP MCP transport**: deferred by design (SSE resume/ordering subtlety); README states stdio-only.
4. **report.html in evidence pack**: cut-line — `manifest.json` + `VERIFY.md` (curl/openssl recipe) are the load-bearing parts; HTML report last.
5. **Key-next-to-ledger**: disclosed, never claim tamper-*proof*; HSM/TPM = roadmap. Truncation window ≤60 s disclosed. `ts` is a claim; Rekor `integratedTime` is the only trusted time.
6. **`npx`-wrapped servers**: recorded argv doesn't pin server code identity — evidence-pack docs say so.
7. **Rekor v1 freeze / rate limits**: URL env-configurable; queue+backoff; v2 writer is additive (same digest payload). Watch for deprecation notice.
8. **TS 7.0.2 toolchain**: newest major; if d.ts emit breaks, pin `typescript@^5.9`.
9. **Windows**: unsupported for MVP (no cross-spawn, POSIX fsync/lockfile assumptions) — stated in README.