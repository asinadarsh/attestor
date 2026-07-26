# Attestor

[![CI](https://github.com/asinadarsh/attestor/actions/workflows/ci.yml/badge.svg)](https://github.com/asinadarsh/attestor/actions/workflows/ci.yml)

**A tamper-evident flight recorder for AI agents.**

Your agents are calling tools that move money and touch PHI; when a regulator
or incident review asks *"what exactly did the agent do,"* a mutable app log
is not an answer. Attestor records every tool call into a hash-chained,
per-entry-signed ledger, checkpoints it with RFC 6962 Merkle roots, and
anchors each root in [Sigstore's public Rekor transparency log](https://docs.sigstore.dev/logging/overview/) —
so tampering with any recorded call breaks verification loudly, and even
rewriting the whole ledger with stolen keys can't beat the public log.

```sh
git clone https://github.com/asinadarsh/attestor && cd attestor && npm install
node packages/attestor/src/cli.ts demo tamper
# 30 seconds: record → verify green → attacker edits → caught → attacker re-signs everything → still caught
```

The demo is offline by default and writes nothing to any public log; `--live`
opts in to a real Sigstore anchor.

```
✔ CHAIN    15 entries, hash chain intact
✔ MERKLE   1 checkpoint, all roots reproduce
✔ SIG      15/15 entry signatures valid (key 37f92a70955fa3b5)
✔ ANCHOR   1/1 anchor recorded (latest logIndex 2256596856), SET+inclusion authenticated
RESULT: VERIFIED  (exit 0)

--- attacker edits the ledger ---
✖ CHAIN    entry 7 payload does not match its signed commitment (payload mutated)
           blast radius: entries 7–14 untrustworthy
RESULT: TAMPER DETECTED  (exit 1)
```

One runtime dependency ([`canonicalize`](https://www.npmjs.com/package/canonicalize),
the RFC 8785 JCS implementation). Everything else is `node:crypto` and `fetch`.
Node ≥ 24, Linux/macOS.

## Record an MCP server (no code changes)

```sh
attestor install                # wraps every server in .mcp.json / Claude Desktop config (with backup)
# or by hand — prepend "attestor wrap --" to any stdio MCP server:
attestor wrap -- npx -y @modelcontextprotocol/server-github
```

The proxy is an opaque byte relay with a recording tap: it never re-serializes
a message, so notifications, server→client requests, and future protocol
methods pass through untouched. Unparsable lines are relayed *and* recorded.
Default failure mode is `--on-error block` (fail closed): if the ledger can't
be written, tool calls get a synthesized JSON-RPC `-32000` error instead of
running unrecorded. `--on-error continue` relays anyway and records a signed
**gap marker** — the ledger is honest about its own holes.

## Record a non-MCP app (one line)

```ts
import { Attestor } from "attestor/sdk";

const attestor = new Attestor();
const anthropic = new Anthropic({ fetch: attestor.wrapFetch() });  // also: new OpenAI({ fetch: ... })

// the HTTP tap sees the model REQUEST the tool and your app REPORT the result.
// attest what your app actually did in between:
await attestor.record({ tool_use_id, name: "payments_transfer", input, output });
```

`wrapFetch()` records exact request/response bytes (SSE streams are teed
without back-pressuring your app) and indexes Anthropic `tool_use` /
OpenAI `tool_calls` + `function_call` structures, streaming or not.

## Verify

```sh
attestor verify <dir>            # CHAIN → MERKLE → SIG → ANCHOR, offline
attestor verify <dir> --online   # + compare every anchor against the public Rekor log
```

Exit codes: `0` verified · `1` tamper · `2` usage/IO error · `3` Rekor
unreachable (CI can tell network from tamper). On tamper you get the entry,
the reason, the blast radius, and an `audit-packet.json`.

**What the trust model actually is.** A Rekor log key shipped *inside* an
evidence pack cannot authenticate that pack — an attacker who forges anchors
would ship a matching key. So attestor separates the two questions: an anchor
verified only against the key packaged with it is reported as
`⚠ UNAUTHENTICATED`, never as proof. Authenticity needs a key you trust
independently — `--online` (fetched live from the log) or a host-pinned
`~/.attestor/keys/rekor-pub.pem`. `--online` also queries the log by your
recorder key, so anchors deleted from a local ledger still surface.

## Evidence packs

```sh
attestor export <ledger-dir>     # → attestor-pack-<date>/
```

Self-contained: ledger, Rekor anchor records (SET + inclusion proofs), public
keys, `manifest.json` with the SHA-256 of every file, `report.html`, and a
`VERIFY.md` whose **curl + jq + openssl recipe verifies the anchors without
installing attestor** — an auditor does not have to trust our binary.
Control mappings (SOC 2 CC7.2/CC7.3/CC4.1, EU AI Act Art. 12, HIPAA
§164.312(b)) claim *supports evidence for* — never certification.

## Threat model

| Attacker capability | Defeated by | Status |
|---|---|---|
| Edit any past entry | hash chain + per-entry sig breaks | ✅ in scope |
| Delete a middle entry | `prev` mismatch + `seq` gap | ✅ |
| Reorder entries | `prev` chain + `seq` | ✅ |
| Truncate tail (delete newest) | chain stays valid locally; signed checkpoint anchored in Rekor at size *N* proves the log was longer. **Window: entries since last anchor are silently truncatable** | ✅ post-anchor / ⚠️ ≤60 s window |
| Fork/rollback (show auditor an alternate history) | two Rekor entries under the same `ledger_id`+pubkey with inconsistent roots = cryptographic fork proof; `verify --online` compares anchored checkpoints against the public log | ✅ if verifier queries Rekor |
| Steal signing key (disk access) | cannot rewrite anchored history without Rekor collusion; **can** forge/fork from theft onward. Rotation bounds blast radius | ⚠️ partial — forward forgery out of scope |
| Root on host *during* recording | nothing — recorder signs what it saw; lies fed to it are faithfully attested | ❌ out of scope, say so |
| Delete entire ledger | Rekor entries under the pubkey survive as existence evidence; absence of a ledger proves nothing about activity | ⚠️ detection only |
| Compromise of Rekor itself | out of scope; Rekor's own witness/monitor ecosystem | ❌ out of scope |

## Honest limits (read before you rely on this)

- **Tamper-EVIDENT, not tamper-proof.** The signing key lives next to the
  ledger (`~/.attestor/keys`, 0600, optional scrypt passphrase). An attacker
  with the key can forge *from theft onward* — but cannot rewrite history
  whose roots are already in Rekor. HSM/TPM support is roadmap, not MVP.
- **Entry `ts` is a claim** by the local clock. The only trusted time is
  Rekor's `integratedTime`.
- **Truncation window**: entries after the last anchored checkpoint
  (≤ 64 entries or ≤ 60 s by default) can be silently dropped. `verify`
  reports this as ANCHOR LAG rather than pretending otherwise.
- **The proxy records transport traffic, not truth.** A malicious tool server
  can lie in its responses; Attestor proves *what was said*, not *what was
  done*. `record()` exists so your app can attest the doing.
- **`npx`-wrapped servers**: the recorded `argv` does not pin server code
  identity. No binary attestation is claimed.
- **stdio only** for MVP. Streamable-HTTP MCP proxying is deferred by design
  (SSE resume/ordering is genuinely subtle; punting beats shipping it
  half-right). Claude Desktop / Claude Code local servers are stdio.
- **Windows unsupported** for MVP (POSIX fsync/lockfile assumptions).
- **Anchoring is a public write.** Each anchor puts a digest, your recorder
  public key, and a timestamp permanently into a shared transparency log.
  Nothing sensitive leaves your machine, but *that you were active, and when,
  and roughly how often* becomes inferable by anyone. Point
  `ATTESTOR_REKOR_URL` at your own Rekor if that matters.
- **No published latency numbers yet.** `--on-error block` with
  `--durability strict` puts an fsync in the path of every tool call. Tool
  calls take 10 ms–10 s so it should be noise, but nothing in this repo
  measures it — treat the overhead as unquantified until it is.
- **Key rotation** is manual (`attestor keys rotate`, old key signs the new
  one into the chain). No revocation list.
- **Rekor v1** REST API, URL configurable via `ATTESTOR_REKOR_URL`; v1 gets
  ≥ 1 year freeze notice, and a v2 writer is additive (same digest payload).

## Design notes

- **Merkle**: RFC 6962 byte-for-byte — `leaf = SHA256(0x00‖h)`,
  `node = SHA256(0x01‖L‖R)`, unbalanced trees per §2.1; verification follows
  RFC 9162 §2.1.3.2/§2.1.4.2; tested against the CT known-answer vectors.
- **Signing**: ECDSA **P-256** + SHA-256 via `node:crypto`, because Rekor's
  `hashedrekord` verifies over a pre-hashed digest, which pure Ed25519 cannot
  do ([rekor#851](https://github.com/sigstore/rekor/issues/851)) — the
  Ed25519+hashedrekord combo ships a broken anchor. One key signs entries
  *and* checkpoints; validated against the live log before anything was
  built on it.
- **Canonicalization**: RFC 8785 JCS over the flat signed core only
  (strings/ints, no floats). Tool-call payloads are **never canonicalized** —
  they're committed as exact wire bytes via
  `payload_hash = SHA256(salt ‖ bytes)`, which eliminates the JCS float/
  surrogate attack surface structurally and makes redaction possible:
  `attestor redact <seq>` strips a payload while chain, sigs, roots, and
  anchors stay valid. The 16-byte salt is itself unsigned and is deleted with
  the payload, so what survives is a commitment nobody can brute-force — a
  salt that stayed on the line would defeat its own purpose.
- **Storage**: append-only JSONL — the ledger file *is* the exhibit. An
  auditor can `jq` it and re-hash it with a 50-line script in any language.
  Torn final lines (crash) are moved to `ledger.torn`; a newline-terminated
  line that fails hash checks is **never** auto-"recovered" — that's tamper
  evidence, and verify must see it.
- **Vocabulary**: "tamper-evident," never "immutable" or "blockchain."

## CLI

```
attestor keys init|list|rotate      P-256 recorder keys (PKCS#8, 0600)
attestor wrap [opts] -- <cmd...>    record an MCP stdio server
attestor install [--dry-run]        wrap servers in .mcp.json / Claude Desktop config
                                   (each server gets its own ledger)
attestor verify <dir> [--online]    verify a ledger or evidence pack
attestor export <dir> [--out d]     regulator-ready evidence pack
attestor redact <dir> <seq>         strip one payload, keep proofs valid
attestor replay <dir> [--session s] print recorded calls (VCR-style)
attestor demo tamper [--live]       the 30-second pitch (offline by default)
```

Env: `ATTESTOR_HOME` (default `~/.attestor`), `ATTESTOR_REKOR_URL`,
`ATTESTOR_OFFLINE=1` (queue anchors, never POST), `ATTESTOR_LIVE=1`
(opt-in live-network tests).

## Verify my claims, not my prose

`examples/` holds two real evidence packs from one recorded session — one
clean, one with a single byte changed. Both reference the same anchor in
Sigstore's public log, so you can check them against a log I do not control:

```sh
node packages/attestor/src/cli.ts verify examples/pack-2026-07           # exit 0
node packages/attestor/src/cli.ts verify examples/pack-2026-07-TAMPERED  # exit 1
```

See [`examples/README.md`](examples/README.md) for the curl recipe.

## Development

npm-workspaces monorepo: `packages/attestor` (published) +
`packages/toy-mcp-server` (test fixture). `npm test` runs 72 tests on
`node:test` with Node 24 native type stripping — chain round-trips, the CT
Merkle vectors, a 13-case tamper matrix, a real MCP SDK client through the
proxy, SSE tee reconstruction, a mocked Rekor (201/409/429/offline queue),
and SET/inclusion verification against a captured live Rekor entry.

MIT.
