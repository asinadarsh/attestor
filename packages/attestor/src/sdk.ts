// attestor/sdk — record tool calls from non-MCP apps.
// Layer 1: `wrapFetch()` — pass as `fetch` to the Anthropic/OpenAI SDK
// constructors; every API round trip is recorded (exact body bytes), and
// tool-call structure (Anthropic `tool_use`, OpenAI `tool_calls` /
// `function_call`) is extracted from a parsed copy for indexing.
// Layer 2: `record()` — one call to attest what the app actually DID with
// the tool call (the DB write, the email), linked via tool_use_id.
import { join } from 'node:path';
import { attestorHome, generateKey, listKeyIds, loadKey, type KeyPair } from './keys.ts';
import { Checkpointer, lastCheckpointSize } from './checkpoint.ts';
import { anchorCheckpoint, queueAnchorForRetry } from './rekor.ts';
import { Ledger, readEntries, uuidv7, type LedgerEntry } from './ledger.ts';

export interface AttestorOptions {
  /** Ledger directory. Default: $ATTESTOR_HOME/ledgers/sdk */
  ledger?: string;
  /** block (default): a failed ledger write rejects the API call. continue: log + gap marker. */
  failMode?: 'block' | 'continue';
  durability?: 'strict' | 'group';
  /** Queue anchors instead of POSTing to Rekor. */
  offline?: boolean;
  /** Recorded on every entry, e.g. { agent: "billing-bot", model: "claude-fable-5" }. */
  actor?: Record<string, string>;
  keys?: KeyPair;
}

export interface ExtractedToolCall {
  id: string;
  name: string;
  /** Parsed input/arguments object when parsable, else raw string. */
  input: unknown;
}

export interface RecordInput {
  /** Links to the tool_use id / tool_call id from the model response. */
  tool_use_id?: string;
  name: string;
  input?: unknown;
  output?: unknown;
  error?: string;
  meta?: Record<string, unknown>;
}

/** Extract tool calls from an Anthropic/OpenAI response body (JSON or SSE text). */
export function extractToolCalls(bodyText: string): ExtractedToolCall[] {
  if (/^(event:|data:)/m.test(bodyText)) return extractFromSse(bodyText);
  let body: unknown;
  try {
    body = JSON.parse(bodyText);
  } catch {
    return [];
  }
  const out: ExtractedToolCall[] = [];
  const b = body as {
    content?: { type: string; id?: string; name?: string; input?: unknown }[];
    choices?: { message?: { tool_calls?: { id: string; function?: { name: string; arguments: string } }[] } }[];
    output?: { type: string; call_id?: string; name?: string; arguments?: string }[];
  };
  // Anthropic Messages: content[] blocks of type tool_use
  for (const block of b.content ?? []) {
    if (block.type === 'tool_use' && block.name !== undefined) {
      out.push({ id: block.id ?? '', name: block.name, input: block.input });
    }
  }
  // OpenAI Chat Completions: choices[].message.tool_calls[]
  for (const choice of b.choices ?? []) {
    for (const tc of choice.message?.tool_calls ?? []) {
      if (tc.function) {
        out.push({ id: tc.id, name: tc.function.name, input: parseMaybe(tc.function.arguments) });
      }
    }
  }
  // OpenAI Responses API: output[] items of type function_call
  for (const item of b.output ?? []) {
    if (item.type === 'function_call' && item.name !== undefined) {
      out.push({ id: item.call_id ?? '', name: item.name, input: parseMaybe(item.arguments ?? '') });
    }
  }
  return out;
}

function parseMaybe(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return s;
  }
}

/** Reconstruct tool calls from an SSE stream (Anthropic input_json_delta, OpenAI deltas). */
function extractFromSse(sse: string): ExtractedToolCall[] {
  const out: ExtractedToolCall[] = [];
  // index → in-progress accumulation
  const anthropic = new Map<number, { id: string; name: string; json: string }>();
  const openai = new Map<number, { id: string; name: string; args: string }>();
  for (const line of sse.split('\n')) {
    if (!line.startsWith('data:')) continue;
    const data = line.slice(5).trim();
    if (data === '' || data === '[DONE]') continue;
    let ev: {
      type?: string;
      index?: number;
      content_block?: { type: string; id?: string; name?: string };
      delta?: { type?: string; partial_json?: string };
      choices?: { delta?: { tool_calls?: { index: number; id?: string; function?: { name?: string; arguments?: string } }[] } }[];
    };
    try {
      ev = JSON.parse(data);
    } catch {
      continue;
    }
    if (ev.type === 'content_block_start' && ev.content_block?.type === 'tool_use') {
      anthropic.set(ev.index ?? 0, { id: ev.content_block.id ?? '', name: ev.content_block.name ?? '', json: '' });
    } else if (ev.type === 'content_block_delta' && ev.delta?.type === 'input_json_delta') {
      const acc = anthropic.get(ev.index ?? 0);
      if (acc) acc.json += ev.delta.partial_json ?? '';
    } else if (ev.type === 'content_block_stop') {
      const acc = anthropic.get(ev.index ?? 0);
      if (acc) {
        out.push({ id: acc.id, name: acc.name, input: parseMaybe(acc.json || '{}') });
        anthropic.delete(ev.index ?? 0);
      }
    }
    for (const choice of ev.choices ?? []) {
      for (const tc of choice.delta?.tool_calls ?? []) {
        const acc = openai.get(tc.index) ?? { id: '', name: '', args: '' };
        if (tc.id !== undefined) acc.id = tc.id;
        if (tc.function?.name !== undefined) acc.name = tc.function.name;
        acc.args += tc.function?.arguments ?? '';
        openai.set(tc.index, acc);
      }
    }
  }
  for (const acc of openai.values()) {
    if (acc.name !== '') out.push({ id: acc.id, name: acc.name, input: parseMaybe(acc.args || '{}') });
  }
  return out;
}

export class Attestor {
  readonly ledgerDir: string;
  private readonly ledger: Ledger;
  private readonly checkpointer: Checkpointer;
  private readonly failMode: 'block' | 'continue';
  private readonly offline: boolean;
  private readonly actor: Record<string, string> | undefined;
  private readonly sessionId: string;
  private gapCount = 0;
  private gapFrom: string | undefined;
  /** Async record/anchor work that close() must drain. */
  private readonly inFlight = new Set<Promise<unknown>>();

  constructor(opts: AttestorOptions = {}) {
    this.ledgerDir = opts.ledger ?? join(attestorHome(), 'ledgers', 'sdk');
    const keys = opts.keys ?? (listKeyIds().length === 0 ? generateKey() : loadKey());
    this.ledger = Ledger.open(this.ledgerDir, keys, {
      durability: opts.durability ?? 'strict',
    });
    this.failMode = opts.failMode ?? 'block';
    this.offline = opts.offline ?? process.env.ATTESTOR_OFFLINE === '1';
    this.actor = opts.actor;
    this.sessionId = uuidv7();
    this.checkpointer = new Checkpointer(this.ledger, {
      initialCoveredSize: lastCheckpointSize(readEntries(join(this.ledgerDir, 'ledger.jsonl'))),
      onCheckpoint: (entry) => {
        const p = anchorCheckpoint(this.ledger, entry, { offline: this.offline })
          .catch((err) => process.stderr.write(`[attestor] anchor failed: ${(err as Error).message}\n`))
          .finally(() => this.inFlight.delete(p));
        this.inFlight.add(p);
      },
    });
    this.checkpointer.setSession(this.sessionId);
    this.append({
      type: 'session_start',
      origin: 'sdk',
      payload: JSON.stringify({ session_id: this.sessionId, pid: process.pid, started_at: new Date().toISOString() }),
    });
  }

  private append(input: Parameters<Ledger['append']>[0]): LedgerEntry | undefined {
    try {
      if (this.gapCount > 0) {
        this.ledger.append({
          type: 'gap',
          origin: 'sdk',
          session_id: this.sessionId,
          payload: JSON.stringify({ unrecorded_events: this.gapCount, from_ts: this.gapFrom, to_ts: new Date().toISOString() }),
        });
        this.gapCount = 0;
        this.gapFrom = undefined;
      }
      const entry = this.ledger.append({
        ...input,
        session_id: this.sessionId,
        ...(this.actor !== undefined && { actor: this.actor }),
      });
      this.checkpointer.noteActivity();
      return entry;
    } catch (err) {
      if (this.failMode === 'block') throw err;
      this.gapCount++;
      if (this.gapFrom === undefined) this.gapFrom = new Date().toISOString();
      process.stderr.write(`[attestor] unrecorded event (${(err as Error).message})\n`);
      return undefined;
    }
  }

  /**
   * A drop-in `fetch` that records every round trip. Pass to SDK constructors:
   *   new Anthropic({ fetch: attestor.wrapFetch() })
   *   new OpenAI({ fetch: attestor.wrapFetch() })
   */
  wrapFetch(base: typeof fetch = fetch): typeof fetch {
    const wrapped = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      const method = init?.method ?? (input instanceof Request ? input.method : 'GET');
      let bodyText: string | undefined;
      let bodyUnrecordable: string | undefined;
      const rawBody = init?.body;
      if (typeof rawBody === 'string') bodyText = rawBody;
      else if (rawBody instanceof Uint8Array) bodyText = Buffer.from(rawBody).toString('utf8');
      else if (rawBody instanceof ArrayBuffer) bodyText = Buffer.from(rawBody).toString('utf8');
      else if (rawBody instanceof URLSearchParams) bodyText = rawBody.toString();
      else if (typeof Blob !== 'undefined' && rawBody instanceof Blob) {
        bodyText = await rawBody.text().catch(() => undefined);
      } else if (rawBody !== undefined && rawBody !== null) {
        // FormData / ReadableStream: consuming them here would break the send.
        bodyUnrecordable = rawBody.constructor?.name ?? typeof rawBody;
      } else if (input instanceof Request) {
        bodyText = await input.clone().text().catch(() => undefined);
        if (bodyText === '') bodyText = undefined;
      }
      if (bodyUnrecordable !== undefined && this.failMode === 'block') {
        // fail closed rather than record a call whose bytes we cannot attest
        throw new Error(
          `attestor: request body of type ${bodyUnrecordable} cannot be recorded byte-exactly (failMode="block"). ` +
            `Serialize it yourself, or construct Attestor with failMode:"continue" to proceed with a documented gap.`,
        );
      }
      const callId = uuidv7();
      let host = 'unknown';
      try {
        host = new URL(url).host;
      } catch {
        /* keep 'unknown' */
      }
      // flight-recorder semantics: the attempt is on record BEFORE dispatch
      this.append({
        type: 'call_request',
        origin: 'sdk',
        call_id: callId,
        tool: { server: host, name: `${method} ${safePath(url)}` },
        payload:
          bodyText ??
          JSON.stringify({
            attestor_note: 'request body not recordable byte-exactly',
            body_type: bodyUnrecordable ?? 'none',
          }),
      });

      const res = await base(input as Parameters<typeof fetch>[0], init);

      // record from a clone at our own pace; the app's stream is untouched
      const recordClone = res.clone();
      const finalize = (text: string) => {
        const calls = extractToolCalls(text);
        this.append({
          type: 'call_result',
          origin: 'sdk',
          call_id: callId,
          tool: {
            server: host,
            name: calls.length > 0 ? calls.map((c) => c.name).join(',') : `${res.status}`,
          },
          payload: text,
        });
      };
      if (this.failMode === 'block') {
        const isStream = (res.headers.get('content-type') ?? '').includes('text/event-stream');
        if (!isStream) {
          // block mode, non-streaming: record before the app can observe the body
          const text = await recordClone.text();
          finalize(text);
          return res;
        }
      }
      // Streaming (or continue mode): record asynchronously so the app is never
      // back-pressured. A failure here must still leave a mark in the chain —
      // in block mode the recorder cannot reject a response the app already
      // has, so it degrades to an explicit gap rather than silence.
      const pending = recordClone
        .text()
        .then(finalize)
        .catch((err) => {
          process.stderr.write(`[attestor] response record failed: ${(err as Error).message}\n`);
          this.noteUnrecorded();
        })
        .finally(() => this.inFlight.delete(pending));
      this.inFlight.add(pending);
      return res;
    };
    return wrapped as typeof fetch;
  }

  /**
   * Mark that something the recorder saw could not be written. The count is
   * flushed as a signed `gap` entry by the next successful append or by
   * close() — so a swallowed write failure still leaves a mark in the chain.
   */
  private noteUnrecorded(): void {
    this.gapCount++;
    if (this.gapFrom === undefined) this.gapFrom = new Date().toISOString();
  }

  /** Attest what the app actually did between model round trips. */
  record(input: RecordInput): LedgerEntry | undefined {
    return this.append({
      type: 'tool_execution',
      origin: 'sdk',
      ...(input.tool_use_id !== undefined && { call_id: input.tool_use_id }),
      tool: { server: 'app', name: input.name },
      payload: JSON.stringify({
        ...(input.tool_use_id !== undefined && { tool_use_id: input.tool_use_id }),
        name: input.name,
        ...(input.input !== undefined && { input: input.input }),
        ...(input.output !== undefined && { output: input.output }),
        ...(input.error !== undefined && { error: input.error }),
        ...(input.meta !== undefined && { meta: input.meta }),
      }),
    });
  }

  /** Flush a final checkpoint, write session_end, release the ledger. */
  async close(): Promise<void> {
    // drain streaming record work first, so its entries land before session_end
    await Promise.allSettled([...this.inFlight]);
    this.append({ type: 'session_end', origin: 'sdk' });
    this.checkpointer.checkpointNow();
    this.checkpointer.stop();
    // Await the final checkpoint's anchor rather than racing a fixed sleep;
    // whatever misses the deadline stays queued in anchors/pending.jsonl.
    const drained = await Promise.race([
      Promise.allSettled([...this.inFlight]).then(() => true),
      new Promise<boolean>((r) => setTimeout(() => r(false), 5_000).unref?.()),
    ]);
    if (!drained) {
      for (const seq of this.unanchoredCheckpointSeqs()) queueAnchorForRetry(this.ledgerDir, seq);
    }
    this.ledger.close();
  }

  private unanchoredCheckpointSeqs(): number[] {
    const entries = readEntries(join(this.ledgerDir, 'ledger.jsonl'));
    const anchored = new Set<number>();
    for (const e of entries) {
      if (e.type === 'anchor' && e.payload !== undefined) {
        try {
          anchored.add((JSON.parse(e.payload) as { checkpoint_seq: number }).checkpoint_seq);
        } catch {
          /* verify reports malformed anchors */
        }
      }
    }
    return entries.filter((e) => e.type === 'checkpoint' && !anchored.has(e.seq)).map((e) => e.seq);
  }
}

function safePath(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}

export type { LedgerEntry } from './ledger.ts';
export { verifyLedger, renderReport, type VerifyReport } from './verify.ts';
