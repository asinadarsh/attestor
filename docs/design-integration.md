Research complete. All versions and API shapes below were verified live (npm registry, modelcontextprotocol.io spec pages, SDK tarball inspection, Anthropic API reference). Design document follows.

---

# Attestor — MCP Proxy + SDK Integration Design

## 1. Verified ground truth (live, 2026-07-27)

| Thing | Value |
|---|---|
| MCP spec current revision | **2025-11-25** (protocol version string `"2025-11-25"`; schema at `modelcontextprotocol/specification/schema/2025-11-25/schema.ts`) |
| Transports | **stdio** and **Streamable HTTP** only. stdio: newline-delimited JSON-RPC over child stdin/stdout, messages MUST NOT contain embedded newlines, stderr is free-form logging. HTTP: single MCP endpoint, one POST per JSON-RPC message, server replies `application/json` or opens SSE; `Mcp-Session-Id` response header at initialize, echoed by client on all subsequent requests; `MCP-Protocol-Version: 2025-11-25` header required on post-initialize HTTP requests. JSON-RPC batching removed since 2025-06-18. |
| `@modelcontextprotocol/sdk` | **1.29.0** (latest, published 2026-06-04). `dist/esm/types.js`: `LATEST_PROTOCOL_VERSION = '2025-11-25'`, `SUPPORTED_PROTOCOL_VERSIONS = ['2025-11-25','2025-06-18','2025-03-26','2024-11-05','2024-10-07']`. Subpath exports `./client` (`StdioClientTransport` taking `StdioServerParameters {command, args?, env?, cwd?, stderr?}`, `StreamableHTTPClientTransport`, sse, websocket), `./server` (`StdioServerTransport`). Shared `Transport` interface: `start()`, `send(message: JSONRPCMessage, options?)`, `onmessage?<T extends JSONRPCMessage>(message, extra?)`, `onclose`, `onerror`. Deps: zod `^3.25 || ^4`, cross-spawn, express 5, hono. |
| `@anthropic-ai/sdk` | **0.115.0**. Tool-use response block: `{type:"tool_use", id:"toolu_…", name, input}` (`input` is a parsed object); result sent back as user-message block `{type:"tool_result", tool_use_id, content, is_error?}`; `stop_reason:"tool_use"`. Streaming: `content_block_start` with a `tool_use` block, then `content_block_delta` events with `delta.type:"input_json_delta"` (partial JSON string), `content_block_stop`. Constructor accepts a custom `fetch` — this is the tap point. Server-side MCP also exists (`mcp_servers` + `mcp_toolset`, beta `mcp-client-2025-11-20`) — those calls are visible only as HTTP body content, not interceptable as local processes; the fetch tap still records them. |
| `openai` | **6.49.0**. Chat Completions: `message.tool_calls: [{id, type:"function", function:{name, arguments /* JSON string */}}]`, results as `{role:"tool", tool_call_id, content}`. Responses API: output item `{type:"function_call", call_id, name, arguments}`, result input item `{type:"function_call_output", call_id, output}`. Also accepts constructor `fetch`. *(Shapes from training + version live-verified; shapes stable across v4–v6 — synthesis agent should not re-litigate.)* |

## 2. Proxy architecture: raw byte relay, not an SDK Client/Server pair

**Do not build the proxy on `@modelcontextprotocol/sdk` Client+Server re-termination.** Re-terminating means re-serializing every message, negotiating capabilities twice, and breaking on any method the SDK version doesn't know. Instead: **opaque newline-framed byte relay** with a recording tap.

```
host (Claude) ──stdin/stdout──> attestor wrap ──spawn──> real server
                     │ (verbatim line pass-through, both directions)
                     └─> parse copy → async record queue → hash-chained ledger
```

- Split each direction on `\n` (spec guarantees one message per line, no embedded newlines). Forward the **exact original bytes** unmodified. Never re-serialize.
- **Crypto defensibility:** hash the exact wire bytes of each line. No canonicalization step exists to argue about on HN — the ledger commits to what was actually transmitted. `JSON.parse` a copy only to extract index metadata (`method`, `id`, tool name, `isError`); parse failure still relays and records the line with `kind:"unparsed"`.
- Because the relay never interprets messages, **notifications, `notifications/progress`, `notifications/cancelled`, server→client requests (`sampling/createMessage`, `elicitation/create`, roots), and any future 2025-11-25+ methods (tasks, etc.) pass through untouched by construction.** Correlation of request/response pairs is done at read/verify time via `(direction, jsonrpc id)` — ids are independent namespaces per direction.
- Child: `child_process.spawn(cmd, args, {stdio:['pipe','pipe','inherit'], shell:false})` (stderr inherited per spec; `cross-spawn` if Windows matters — it's already what the MCP SDK uses). Propagate child exit code; on parent-stdin EOF close child stdin, drain, flush ledger, exit.
- `@modelcontextprotocol/sdk@^1.29.0` becomes a **devDependency only**: integration tests spin a real `Client` (`StdioClientTransport` pointing at `attestor wrap -- node test-server.js`) and assert initialize/tools/list/tools/call/notification/cancellation transparency. Zero runtime deps in the relay path.

## 3. CLI and config interposition

`attestor wrap [--ledger <dir>] [--on-error block|continue] [--durability group|strict] -- <command> [args…]`

Everything after `--` is the wrapped server command. Before/after for **`claude_desktop_config.json`** (macOS: `~/Library/Application Support/Claude/`) and **Claude Code project `.mcp.json`** — identical `mcpServers` shape (Claude Code additionally accepts `"type": "stdio"`, which is the default):

```jsonc
// BEFORE
{ "mcpServers": { "github": {
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-github"],
    "env": { "GITHUB_TOKEN": "ghp_…" } } } }

// AFTER — prepend attestor wrap --; env unchanged (child inherits it)
{ "mcpServers": { "github": {
    "command": "attestor",
    "args": ["wrap", "--", "npx", "-y", "@modelcontextprotocol/server-github"],
    "env": { "GITHUB_TOKEN": "ghp_…" } } } }
```

Ship `attestor install` that rewrites these files mechanically (backup + idempotent detection of already-wrapped entries) — the diff above is trivially scriptable.

**Transport honesty for MVP:** stdio only, stated plainly. Streamable HTTP is a designed-but-deferred local reverse-proxy mode (`attestor proxy --listen 127.0.0.1:9464 --target https://host/mcp`): forward POST/GET/DELETE, record POST bodies and individual SSE `data:` frames verbatim, key session identity on the `Mcp-Session-Id` header. Deferred because SSE resumability (`Last-Event-ID` replay) and multiple concurrent GET streams make "record exactly once, in order" genuinely subtle — punting is more honest than shipping it half-right. Claude Desktop/Claude Code local servers are stdio, so MVP coverage is the real-world common case; remote HTTP servers used from Claude Code are the gap to disclose.

## 4. Latency budget & async writes

- Relay path cost per message: line-scan + synchronous in-memory enqueue — target **<100µs added, zero I/O on the relay path**. Tool calls take 10ms–10s; the proxy is noise.
- Single writer drains the queue: compute hash chain, append JSONL entry. Durability: **group commit** default (fsync every 25ms or 256 entries, whichever first); `--durability strict` = fsync per entry for regulated deployments. Merkle checkpoint/anchoring runs in the same writer on its own cadence, never touching the relay.
- Backpressure bound (e.g. 64MB queued) — beyond it, the configured failure mode triggers instead of unbounded memory growth.

## 5. Failure semantics

Configurable `--on-error block|continue`. **Default: `block` (fail-closed).** Rationale: the product's only guarantee is completeness of the record; an evidence recorder that silently drops evidence under failure is worse than one that stops — and buyers are compliance teams, not uptime teams. Mechanics in `block` mode when the ledger is unwritable: client→server *requests* get a synthesized JSON-RPC error response (`{code:-32000, message:"attestor: audit ledger unavailable"}`) instead of being forwarded — the agent sees a failed tool call, not a hang; notifications are dropped with a stderr diagnostic. In `continue` mode the relay proceeds and, on ledger recovery, appends an explicit signed **gap marker** entry (count + time range of unrecorded traffic) — the record is honest about its own hole rather than pretending continuity. Gap markers are the HN-defensible version of fail-open.

## 6. Captured identity metadata (per session)

One `session_start` entry per `wrap` invocation: `proxy_session_id` (UUIDv7), wall+monotonic start time, hostname, OS user, proxy pid, wrapped `argv`, cwd, attestor version. From the relayed `initialize` exchange (parsed from the tap, bytes still relayed untouched): `protocolVersion` negotiated, `clientInfo {name, version}` (identifies the agent host — e.g. `claude-ai`), client capabilities, `serverInfo {name, version}`, server capabilities, instructions-hash. Every message entry: direction (`c2s`/`s2c`), wall + monotonic timestamps, byte hash, extracted `method`/`id`/tool name. **Deliberately not recorded: `env`** (secrets). This gives the evidence pack "which agent, which server, which tools, when, in what order" without a trust dependency on the wrapped parties.

## 7. Node SDK for non-MCP tool-calling apps (`@attestor/sdk` — same package, second entry point)

Two layers, laziest-first:

**Layer 1 — fetch tap (zero app changes beyond one line).** Both `@anthropic-ai/sdk@0.115.0` and `openai@6.49.0` accept a custom `fetch` in constructor options:

```ts
import { Attestor } from "@attestor/sdk";
const attestor = new Attestor({ ledger: "~/.attestor/ledger" }); // failMode: "block" default, same semantics as proxy
const anthropic = new Anthropic({ fetch: attestor.wrapFetch() });
const openai = new OpenAI({ fetch: attestor.wrapFetch() });
```

Records every API round trip: URL, method, hash of exact request/response body bytes; a parsed copy extracts and indexes tool-call structure — Anthropic `tool_use` blocks out and `tool_result` blocks in; OpenAI `tool_calls`/`role:"tool"` (Chat Completions) and `function_call`/`function_call_output` (Responses). Streaming: tee the response body stream (record side must never backpressure the app side — buffer and finalize the entry at stream end), accumulating `input_json_delta` frames to reconstruct the complete tool call while also hashing raw SSE bytes. This captures the model *requesting* the tool and the app *reporting* the result — the two ends of every tool call — from unmodified app code.

**Layer 2 — manual record for the middle.** The HTTP tap can't see what the app actually *did* between those two calls (the DB write, the email). One method:

```ts
await attestor.record({ kind: "tool_execution", tool_use_id, name, input, output, error?, meta? });
```

Entries link to the surrounding HTTP entries via `tool_use_id`/`call_id`. That's the whole SDK surface for MVP — no middleware framework, no decorators; `wrapFetch()` + `record()` covers Anthropic, OpenAI, and (bonus, worth one README line) Anthropic's server-side MCP connector calls, since those are just body content on the same tapped requests. Skipped: LangChain/Vercel-AI-SDK adapters — add when someone asks; both ultimately call these two SDKs through fetch anyway.

## 8. Risks to surface in synthesis

1. `npx`-wrapped servers mean the recorded `argv` doesn't pin server code identity — say so in the evidence-pack docs rather than pretending binary attestation.
2. The proxy records transport traffic, not truth: a malicious server can lie in its responses; Attestor proves *what was said*, not *what was done*. Correct framing for the HN audience.
3. stdio framing assumption (one message per line) is spec-mandated; a non-compliant server that emits embedded newlines would corrupt framing for the host too — relay behaves identically to no-proxy, which is the right transparency property.

*Packages: runtime — none for the proxy; `@attestor/sdk` peer-deps none (wraps caller-supplied clients). Dev — `@modelcontextprotocol/sdk@^1.29.0`, `@anthropic-ai/sdk@^0.115.0`, `openai@^6.49.0` for integration tests. Node 24 built-ins (`node:child_process`, `node:crypto`) cover spawn + SHA-256.*