// MCP stdio proxy: opaque newline-framed byte relay with a recording tap.
// Never re-serializes — forwards the exact original bytes, so notifications,
// server→client requests, and future protocol methods pass through untouched.
// A parsed COPY extracts index metadata only; parse failure still relays and
// records the line as an unparsed `wire` entry.
//
// Failure semantics: `--on-error block` (default, fail-closed) — if the
// ledger is unwritable, client→server requests get a synthesized JSON-RPC
// -32000 error instead of being forwarded (the agent sees a failed tool call,
// not a hang); notifications are dropped with a stderr diagnostic; s2c lines
// are still forwarded (the action already happened — hiding the response
// records nothing and misleads the agent). `continue` relays everything and
// appends a signed gap marker on recovery.
import { spawn } from 'node:child_process';
import { hostname, userInfo } from 'node:os';
import { basename } from 'node:path';
import type { Checkpointer } from './checkpoint.ts';
import type { Ledger } from './ledger.ts';
import { uuidv7 } from './ledger.ts';

export interface ProxyOptions {
  ledger: Ledger;
  checkpointer: Checkpointer;
  command: string;
  args: string[];
  onError?: 'block' | 'continue';
  /** Register SIGTERM/SIGINT handlers that finalize the ledger (CLI mode). */
  handleSignals?: boolean;
  stdin?: NodeJS.ReadableStream;
  stdout?: NodeJS.WritableStream;
  stderr?: NodeJS.WritableStream;
}

interface PendingCall {
  tool?: string;
  startedAt: number;
}

/** Split a byte stream into newline-framed lines, preserving exact bytes. */
export function lineSplitter(onLine: (line: Buffer) => void): (chunk: Buffer) => void {
  let rest: Buffer = Buffer.alloc(0);
  return (chunk: Buffer) => {
    let data = rest.length > 0 ? Buffer.concat([rest, chunk]) : chunk;
    for (;;) {
      const nl = data.indexOf(10);
      if (nl === -1) break;
      onLine(data.subarray(0, nl));
      data = data.subarray(nl + 1);
    }
    rest = data;
  };
}

interface ParsedMeta {
  kind: 'request' | 'response' | 'notification' | 'unparsed';
  id?: string;
  method?: string;
  toolName?: string;
  isError?: boolean;
}

export function classifyLine(line: Buffer): ParsedMeta {
  let msg: {
    id?: unknown;
    method?: string;
    params?: { name?: string };
    error?: unknown;
    result?: { isError?: boolean };
  };
  try {
    msg = JSON.parse(line.toString('utf8'));
  } catch {
    return { kind: 'unparsed' };
  }
  if (msg === null || typeof msg !== 'object') return { kind: 'unparsed' };
  if (msg.method !== undefined) {
    if (msg.id === undefined) {
      return { kind: 'notification', method: msg.method };
    }
    return {
      kind: 'request',
      id: String(msg.id),
      method: msg.method,
      ...(msg.method === 'tools/call' && msg.params?.name !== undefined && { toolName: msg.params.name }),
    };
  }
  if (msg.id !== undefined) {
    return {
      kind: 'response',
      id: String(msg.id),
      isError: msg.error !== undefined || msg.result?.isError === true,
    };
  }
  return { kind: 'unparsed' };
}

export function runProxy(opts: ProxyOptions): Promise<number> {
  const { ledger, checkpointer } = opts;
  const onError = opts.onError ?? 'block';
  const stdin = opts.stdin ?? process.stdin;
  const stdout = opts.stdout ?? process.stdout;
  const stderr = opts.stderr ?? process.stderr;
  const sessionId = uuidv7();
  checkpointer.setSession(sessionId);

  const serverName = basename(opts.command);
  const pendingCalls = new Map<string, PendingCall>(); // c2s request id → call meta
  let ledgerBroken = false;
  let gapCount = 0;
  let gapFrom: string | undefined;

  const diag = (msg: string) => stderr.write(`[attestor] ${msg}\n`);

  const record = (input: Parameters<Ledger['append']>[0]): boolean => {
    try {
      if (ledgerBroken && gapCount > 0) {
        // recovery attempt: write the gap marker first
        const marker = {
          type: 'gap' as const,
          origin: 'proxy' as const,
          session_id: sessionId,
          payload: JSON.stringify({ unrecorded_lines: gapCount, from_ts: gapFrom, to_ts: new Date().toISOString() }),
        };
        ledger.append(marker);
        gapCount = 0;
        gapFrom = undefined;
        ledgerBroken = false;
      }
      ledger.append({ ...input, session_id: sessionId });
      checkpointer.noteActivity();
      return true;
    } catch (err) {
      if (!ledgerBroken) diag(`ledger write failed: ${(err as Error).message}`);
      ledgerBroken = true;
      gapCount++;
      if (gapFrom === undefined) gapFrom = new Date().toISOString();
      return false;
    }
  };

  record({
    type: 'session_start',
    origin: 'proxy',
    payload: JSON.stringify({
      session_id: sessionId,
      argv: [opts.command, ...opts.args],
      cwd: process.cwd(),
      hostname: hostname(),
      os_user: userInfo().username,
      proxy_pid: process.pid,
      started_at: new Date().toISOString(),
    }),
  });

  const child = spawn(opts.command, opts.args, {
    stdio: ['pipe', 'pipe', 'inherit'],
    shell: false,
  });

  return new Promise<number>((resolve) => {
    let settled = false;
    let finalized = false;
    // Synchronous final writes — safe to run from a signal handler, because
    // ledger appends are sync (writeSync + fsync).
    const finalize = () => {
      if (finalized) return;
      finalized = true;
      record({ type: 'session_end', origin: 'proxy' });
      checkpointer.checkpointNow();
      checkpointer.stop();
    };
    const finish = (code: number) => {
      if (settled) return;
      settled = true;
      finalize();
      if (opts.handleSignals) {
        process.off('SIGTERM', onSignal);
        process.off('SIGINT', onSignal);
      }
      resolve(code);
    };
    const onSignal = () => {
      finalize();
      child.kill('SIGTERM');
    };
    if (opts.handleSignals) {
      process.on('SIGTERM', onSignal);
      process.on('SIGINT', onSignal);
    }

    child.on('error', (err) => {
      diag(`failed to spawn ${opts.command}: ${err.message}`);
      finish(127);
    });

    // ---- client → server ----
    const c2s = lineSplitter((line) => {
      const meta = classifyLine(line);
      const payload = line.toString('utf8');
      const entryInput = {
        type: meta.kind === 'request' && meta.method === 'tools/call' ? ('call_request' as const) : ('wire' as const),
        origin: 'proxy' as const,
        direction: 'c2s' as const,
        payload,
        ...(meta.id !== undefined && { call_id: `c2s:${meta.id}` }),
        ...(meta.toolName !== undefined && { tool: { server: serverName, name: meta.toolName } }),
      };
      const recorded = record(entryInput);
      if (!recorded && onError === 'block') {
        if (meta.kind === 'request') {
          // fail the call loudly instead of forwarding unrecorded traffic
          let id: unknown = meta.id;
          try {
            id = (JSON.parse(payload) as { id?: unknown }).id;
          } catch {
            /* meta.id stands */
          }
          stdout.write(
            JSON.stringify({
              jsonrpc: '2.0',
              id,
              error: { code: -32000, message: 'attestor: audit ledger unavailable — call blocked (on-error=block)' },
            }) + '\n',
          );
        } else {
          diag(`dropped unrecordable ${meta.kind} (on-error=block)`);
        }
        return;
      }
      if (meta.kind === 'request') {
        pendingCalls.set(meta.id!, {
          ...(meta.toolName !== undefined && { tool: meta.toolName }),
          startedAt: Date.now(),
        });
      }
      child.stdin.write(Buffer.concat([line, Buffer.from('\n')]));
    });

    // ---- server → client ----
    const s2c = lineSplitter((line) => {
      const meta = classifyLine(line);
      const pending = meta.kind === 'response' && meta.id !== undefined ? pendingCalls.get(meta.id) : undefined;
      if (meta.kind === 'response' && meta.id !== undefined) pendingCalls.delete(meta.id);
      record({
        type: pending?.tool !== undefined ? 'call_result' : 'wire',
        origin: 'proxy',
        direction: 's2c',
        payload: line.toString('utf8'),
        ...(meta.id !== undefined && { call_id: `c2s:${meta.id}` }),
        ...(pending?.tool !== undefined && { tool: { server: serverName, name: pending.tool } }),
      });
      // s2c always forwarded — the action already happened server-side;
      // suppressing the response would hide it from the agent, not undo it.
      stdout.write(Buffer.concat([line, Buffer.from('\n')]));
    });

    stdin.on('data', c2s);
    stdin.on('end', () => {
      child.stdin.end();
    });
    child.stdout.on('data', s2c);
    child.on('close', (code, signal) => {
      finish(code ?? (signal ? 128 + 15 : 0));
    });
  });
}
