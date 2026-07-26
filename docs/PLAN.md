# Attestor — Build Plan (MVP, complete)

## Context

Attestor ranked #1 (68/100, only zero-kill-vote candidate) in the YC opportunity research of 2026-07-27: a tamper-evident flight recorder for AI agents — hash-chained ledger of every agent tool call, externally anchored to a public transparency log, with a verify CLI and regulator-ready evidence packs. User branched the session to build it end-to-end. Decisions locked with user: **full MVP**, **TypeScript/Node 24**, **Sigstore Rekor anchoring**, **~/attestor public GitHub repo (`asinadarsh`)**. Design was produced by a 4-agent workflow (3 live-spec research perspectives + synthesis); full design docs in workflow `wf_e1144d61-2c3` journal. This plan is the synthesis blueprint, decided — no open options.

## Architecture (final)

**One published npm package `attestor`** (bin + `attestor/sdk` subpath export) in an npm-workspaces monorepo; second private workspace `toy-mcp-server` (~60-line echo-tool MCP server) for tests + demo.

```
~/attestor/
  package.json                # private, workspaces
  README.md                   # threat-model table + Show HN pitch
  packages/attestor/src/      # cli.ts ledger.ts keys.ts merkle.ts checkpoint.ts
                              # rekor.ts verify.ts proxy.ts sdk.ts export.ts redact.ts demo.ts
  packages/attestor/test/     # node:test + vectors/ (RFC 6962 known answers, live Rekor fixture)
  packages/toy-mcp-server/
```

**Crypto core**: append-only `ledger.jsonl` (one JSON/line, pid lockfile, O_APPEND, fsync-per-entry default `strict`, `--durability group` opt-in). Signed core per entry: `v, seq, ts, type, session_id, call_id?, direction?, origin, actor?, tool?, salt, payload_hash, prev, key_id` — canonicalized with RFC 8785 JCS (`canonicalize@3.0.0`, the ONLY runtime dep), hashed SHA-256, signed **ECDSA P-256** (`node:crypto`, PKCS#8 at `~/.attestor/keys/`, 0600). `payload` (exact wire bytes) is UNSIGNED but committed via `payload_hash = SHA256(salt‖bytes)` → `attestor redact` strips payloads without breaking chain/sigs (salted commitment defeats brute-force). Entry types: genesis (embeds pubkey), session_start/end, wire, call_request (written BEFORE execution), call_result, tool_execution, checkpoint, anchor, gap, key_rotation.

**Merkle/anchoring**: RFC 6962 tree (0x00/0x01 prefixes) over entry hashes; checkpoint at 64 entries ∨ 60 s idle ∨ session end. Checkpoint entry's JCS core bytes → `hashedrekord` POST to `rekor.sigstore.dev/api/v1/log/entries` (P-256 chosen because Rekor v2 drops Ed25519+rekord). Full Rekor response stored in `anchors/`, pending queue + jittered backoff when offline; anchoring never blocks recording.

**Proxy**: `attestor wrap -- <server cmd>` — stdio JSON-RPC byte relay with tap; records initialize/tools-list/call pairs + timestamps; unparsable lines relayed and recorded as `wire`. `--on-error block` default (ledger write fails → synthesized JSON-RPC -32000, no silent loss), `continue` mode appends gap markers. `attestor install` edits `.mcp.json`/`claude_desktop_config.json`. Stdio-only for MVP (HTTP transport deferred, disclosed).

**SDK** (`attestor/sdk`): `Attestor.wrapFetch()` middleware capturing Anthropic `tool_use` / OpenAI `tool_calls` bodies + `record()` for manual linkage; SSE tee for streaming (cut-line: non-streaming first).

**Verify CLI**: checks CHAIN → MERKLE → SIG → ANCHOR (offline) → ANCHOR-ONLINE (fresh Rekor proof, defeats full-rewrite-with-stolen-key). Exit codes 0/1/2/3. Loud `TAMPER DETECTED at entry N` + blast radius + audit-packet.json.

**Evidence pack** (`attestor export`): manifest.json, entries, proofs, checkpoint sigs, `VERIFY.md` (curl/openssl recipe so an auditor needs no attestor install), honest control mappings (SOC2 CC-series, EU AI Act Art. 12, HIPAA audit controls — support, never certification claims). report.html last (cut-line).

**Demo** (`attestor demo tamper`, ~30 s): record 12 calls incl. `payments.transfer 100.00` → green verify → byte-edit to `100000.00` → TAMPER DETECTED, field diff, blast radius, exit 1 → kicker: attacker re-signs entire ledger, `verify --online` catches it against the public log.

## Dependencies (verified live 2026-07-27)

Runtime: `canonicalize@3.0.0` only. Dev: `typescript@7.0.2` (fallback pin `^5.9` if d.ts emit breaks), `@types/node@^24`, `@modelcontextprotocol/sdk@1.29.0`, `@anthropic-ai/sdk@0.115.0`, `openai@6.49.0`, `@sigstore/rekor-types@5.0.0`. Tests: `node:test`, Node 24 native type-stripping.

## Build order

0. **Spike (mandatory first)**: throwaway live POST of P-256 hashedrekord to rekor.sigstore.dev; capture response as test fixture. Validates key/format decision before anything is built on it.
1. Ledger core + keys (~450 LoC) → 2. Merkle + checkpoint (250) → 3. verify offline (350) → 4. Rekor anchor + `--online` + SET verify (300) → 5. MCP stdio proxy (250) → 6. SDK (250) → 7. Evidence pack (300) → 8. redact/replay/demo (250). ~2.4k LoC. Tests land with each component, not at the end.

Then: README (threat model verbatim, honest limits: key-next-to-ledger disclosed — "tamper-EVIDENT, not tamper-proof"; ts is a claim, Rekor integratedTime is trusted time; Windows unsupported; stdio-only), git history in sensible commits, `gh repo create asinadarsh/attestor --public --push`.

Ultracode: implementation runs inline (single tightly-coupled codebase — parallel agents would collide), then a multi-agent adversarial review workflow (crypto lens, tamper-matrix lens, proxy-correctness lens) before publish; fixes applied, re-verified.

## Test plan (automated)

- Chain round-trip, seq monotonicity, lockfile exclusion, torn-tail recovery.
- Tamper matrix — each exits 1 with correct blast radius: core-field mutation, payload mutation (payload_hash), deleted line, swapped lines, post-anchor truncation, re-sign with foreign key; redacted entry must still PASS.
- Merkle: RFC 6962 known-answer vectors sizes 1–8, inclusion proof per leaf, consistency between checkpoints, unbalanced sizes.
- Proxy: real MCP SDK client through `attestor wrap -- toy-mcp-server` — byte-identical relay, notifications pass, block-mode -32000, gap markers.
- SDK: Anthropic/OpenAI body extraction against stubs; SSE tee.
- Rekor: `node:http` mock asserting exact body, 201/409 paths, retry/backoff, SET verify against spike fixture; opt-in live smoke (`ATTESTOR_LIVE=1`).
- E2E: `attestor demo tamper --offline` asserts exit 0 then exit 1.

## Verification (end-to-end)

1. `npm test` green across workspaces.
2. Real MCP round-trip: Claude-Code-style client through wrapped toy server; verify ledger, checkpoint, verify CLI PASS.
3. Live anchor: one real Rekor entry (spike + smoke), `verify --online` PASS; then tamper → FAIL loudly.
4. `attestor demo tamper` full run — green→red→kicker exactly as scripted.
5. `attestor export` pack opens; VERIFY.md recipe re-verifies with curl+openssl alone.
6. Repo public on GitHub, README accurate to what shipped.

## Cut-lines (in order, all disclosed if taken)

SET verify → experimental flag; SDK streaming tee → non-streaming only; report.html → manifest+VERIFY.md; HTTP MCP transport → deferred by design.
