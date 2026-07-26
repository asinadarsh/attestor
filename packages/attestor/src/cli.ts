#!/usr/bin/env node
// attestor CLI: keys, wrap, install, verify, export, redact, replay, demo.
import { parseArgs } from 'node:util';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, copyFileSync } from 'node:fs';
import { homedir, platform } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { attestorHome, generateKey, listKeyIds, loadKey } from './keys.ts';
import { Ledger, readEntries, uuidv7, type LedgerEntry } from './ledger.ts';
import { Checkpointer, lastCheckpointSize } from './checkpoint.ts';
import { anchorCheckpoint, queueAnchorForRetry, retryPending } from './rekor.ts';
import { renderReport, verifyLedger } from './verify.ts';
import { runProxy } from './proxy.ts';

const USAGE = `attestor — tamper-evident flight recorder for AI agents

Usage:
  attestor keys init [--passphrase-file <f>]     generate a P-256 recorder key
  attestor keys list                             list recorder keys (active last)
  attestor keys rotate --ledger <dir>            rotate: new key signed into the chain by the old one
  attestor wrap [opts] -- <server command...>    record an MCP stdio server
  attestor install [--config <file>] [--dry-run] wrap every server in .mcp.json / Claude Desktop config
  attestor verify <dir> [--online] [--entry N] [--json]
  attestor export <ledger-dir> [--out <dir>]     write a regulator-ready evidence pack
  attestor redact <ledger-dir> <seq>             strip a payload (chain & sigs stay valid)
  attestor replay <ledger-dir> [--session <id>]  print recorded tool calls
  attestor demo tamper [--offline]               30-second tamper-evidence demo

Options:
  --ledger <dir>        ledger directory (default $ATTESTOR_HOME/ledgers/default)
  --on-error <mode>     block | continue         (default block: fail closed)
  --durability <mode>   strict | group           (default strict: fsync per entry)
  --offline             queue anchors, never touch the network
  --online              verify against the public Rekor log too
Env: ATTESTOR_HOME, ATTESTOR_REKOR_URL, ATTESTOR_OFFLINE=1, ATTESTOR_LIVE=1

Exit codes (verify): 0 verified · 1 tamper · 2 usage/IO error · 3 Rekor unreachable`;

function fail(msg: string): never {
  process.stderr.write(`attestor: ${msg}\n`);
  process.exit(2);
}

/**
 * Ledger directory. A ledger has a single writer (O_EXCL lockfile), so each
 * wrapped server gets its own — otherwise Claude Desktop launching two servers
 * concurrently would leave all but one attestor dead on "ledger locked".
 */
function defaultLedgerDir(command?: string, args: string[] = []): string {
  if (command === undefined) return join(attestorHome(), 'ledgers', 'default');
  const label = [command, ...args].join(' ');
  const slug =
    basename(command).replace(/[^a-zA-Z0-9._-]/g, '') || 'server';
  const digest = createHash('sha256').update(label).digest('hex').slice(0, 8);
  return join(attestorHome(), 'ledgers', `${slug}-${digest}`);
}

function loadOrInitKeys(passphrase?: string) {
  if (listKeyIds().length === 0) {
    const pair = generateKey(attestorHome(), passphrase);
    process.stderr.write(`[attestor] generated recorder key ${pair.keyId} at ${attestorHome()}/keys\n`);
    return pair;
  }
  return loadKey(attestorHome(), undefined, passphrase);
}

function readPassphrase(file?: string): string | undefined {
  if (file === undefined) return undefined;
  return readFileSync(file, 'utf8').trim();
}

// ---------------- subcommands ----------------

async function cmdKeys(argv: string[]): Promise<void> {
  const sub = argv[0];
  const { values } = parseArgs({
    args: argv.slice(1),
    options: {
      ledger: { type: 'string' },
      'passphrase-file': { type: 'string' },
    },
  });
  const passphrase = readPassphrase(values['passphrase-file']);
  if (sub === 'init') {
    const pair = generateKey(attestorHome(), passphrase);
    process.stdout.write(`generated P-256 recorder key ${pair.keyId}\n  private: ${attestorHome()}/keys/${pair.keyId}.pem (0600${passphrase !== undefined ? ', scrypt-encrypted' : ''})\n  public:  ${attestorHome()}/keys/${pair.keyId}.pub\n`);
    return;
  }
  if (sub === 'list') {
    const ids = listKeyIds();
    if (ids.length === 0) {
      process.stdout.write('no keys — run: attestor keys init\n');
      return;
    }
    ids.forEach((id, i) => {
      process.stdout.write(`${id}${i === ids.length - 1 ? '  (active)' : ''}\n`);
    });
    return;
  }
  if (sub === 'rotate') {
    const dir = values.ledger ?? defaultLedgerDir();
    if (!existsSync(join(dir, 'ledger.jsonl'))) fail(`no ledger at ${dir} — rotation is recorded in the chain`);
    const oldKeys = loadKey(attestorHome(), undefined, passphrase);
    const ledger = Ledger.open(dir, oldKeys);
    const newKeys = generateKey(attestorHome(), passphrase);
    ledger.append({
      type: 'key_rotation',
      origin: 'system',
      payload: newKeys.publicPem,
    });
    ledger.close();
    process.stdout.write(`rotated ${oldKeys.keyId} → ${newKeys.keyId} (rotation entry signed by the old key)\n`);
    return;
  }
  fail(`unknown keys subcommand: ${sub ?? '(none)'}\n\n${USAGE}`);
}

async function cmdWrap(argv: string[]): Promise<void> {
  const sep = argv.indexOf('--');
  if (sep === -1 || sep === argv.length - 1) fail('usage: attestor wrap [opts] -- <server command...>');
  const { values } = parseArgs({
    args: argv.slice(0, sep),
    options: {
      ledger: { type: 'string' },
      'on-error': { type: 'string', default: 'block' },
      durability: { type: 'string', default: 'strict' },
      offline: { type: 'boolean', default: false },
      'passphrase-file': { type: 'string' },
    },
  });
  const command = argv[sep + 1]!;
  const args = argv.slice(sep + 2);
  const onError = values['on-error'] as 'block' | 'continue';
  if (!['block', 'continue'].includes(onError)) fail(`--on-error must be block|continue`);
  const durability = values.durability as 'strict' | 'group';
  if (!['strict', 'group'].includes(durability)) fail(`--durability must be strict|group`);

  const keys = loadOrInitKeys(readPassphrase(values['passphrase-file']));
  const dir = values.ledger ?? defaultLedgerDir(command, args);
  const ledger = Ledger.open(dir, keys, { durability });
  if (ledger.tornRecovery.recovered) {
    process.stderr.write(`[attestor] recovered torn tail (${ledger.tornRecovery.tornBytes} bytes → ledger.torn)\n`);
  }
  const offline = values.offline || process.env.ATTESTOR_OFFLINE === '1';
  // Track in-flight anchors so shutdown can await them instead of racing a
  // fixed sleep — otherwise the final checkpoint's anchor is lost entirely.
  const inFlight = new Set<Promise<unknown>>();
  const checkpointer = new Checkpointer(ledger, {
    initialCoveredSize: lastCheckpointSize(readEntries(join(dir, 'ledger.jsonl'))),
    onCheckpoint: (entry) => {
      const p = anchorCheckpoint(ledger, entry, { offline })
        .catch((err) => process.stderr.write(`[attestor] anchor failed: ${(err as Error).message}\n`))
        .finally(() => inFlight.delete(p));
      inFlight.add(p);
    },
  });
  if (!offline) {
    const p = retryPending(ledger)
      .catch(() => {})
      .finally(() => inFlight.delete(p));
    inFlight.add(p);
  }
  const code = await runProxy({ ledger, checkpointer, command, args, onError, handleSignals: true });
  // Drain in-flight anchors, but never hang a shutdown on a slow log: whatever
  // has not landed by the deadline is queued for the next run to retry.
  const drained = await Promise.race([
    Promise.allSettled([...inFlight]).then(() => true),
    new Promise<boolean>((r) => setTimeout(() => r(false), 5_000).unref?.()),
  ]);
  if (!drained) {
    for (const seq of pendingCheckpointSeqs(ledger, dir)) queueAnchorForRetry(dir, seq);
    process.stderr.write('[attestor] anchor still in flight at exit — queued for retry\n');
  }
  ledger.close();
  process.exit(code);
}

/** Checkpoints with no matching anchor entry and no stored anchor file. */
function pendingCheckpointSeqs(ledger: Ledger, dir: string): number[] {
  const entries = readEntries(join(dir, 'ledger.jsonl'));
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

interface McpServerDef {
  command: string;
  args?: string[];
  [k: string]: unknown;
}

export function wrapConfig(config: { mcpServers?: Record<string, McpServerDef> }): {
  changed: string[];
  skipped: string[];
} {
  const changed: string[] = [];
  const skipped: string[] = [];
  for (const [name, def] of Object.entries(config.mcpServers ?? {})) {
    if (def.command === 'attestor' || (def.command?.endsWith('/attestor') ?? false)) {
      skipped.push(name);
      continue;
    }
    def.args = ['wrap', '--', def.command, ...(def.args ?? [])];
    def.command = 'attestor';
    changed.push(name);
  }
  return { changed, skipped };
}

async function cmdInstall(argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: {
      config: { type: 'string' },
      'dry-run': { type: 'boolean', default: false },
    },
  });
  let configPath = values.config;
  if (configPath === undefined) {
    const candidates = [
      resolve('.mcp.json'),
      platform() === 'darwin'
        ? join(homedir(), 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
        : join(homedir(), '.config', 'Claude', 'claude_desktop_config.json'),
    ];
    configPath = candidates.find((p) => existsSync(p));
    if (configPath === undefined) fail('no .mcp.json or Claude Desktop config found — pass --config <file>');
  }
  const config = JSON.parse(readFileSync(configPath, 'utf8')) as { mcpServers?: Record<string, McpServerDef> };
  const { changed, skipped } = wrapConfig(config);
  for (const s of skipped) process.stdout.write(`already wrapped: ${s}\n`);
  if (changed.length === 0) {
    process.stdout.write('nothing to change\n');
    return;
  }
  if (values['dry-run']) {
    process.stdout.write(JSON.stringify(config, null, 2) + '\n');
    return;
  }
  copyFileSync(configPath, configPath + '.bak');
  writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');
  process.stdout.write(`wrapped ${changed.join(', ')} in ${configPath} (backup: ${configPath}.bak)\n`);
}

async function cmdVerify(argv: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      online: { type: 'boolean', default: false },
      entry: { type: 'string' },
      json: { type: 'boolean', default: false },
      'rekor-url': { type: 'string' },
      'rekor-key': { type: 'string' },
    },
  });
  const target = positionals[0] ?? defaultLedgerDir();
  if (values.entry !== undefined && !/^\d+$/.test(values.entry)) {
    fail(`--entry must be a non-negative integer, got "${values.entry}"`);
  }
  const report = await verifyLedger(target, {
    online: values.online,
    ...(values.entry !== undefined && { entry: Number(values.entry) }),
    ...(values['rekor-url'] !== undefined && { rekorUrl: values['rekor-url'] }),
    ...(values['rekor-key'] !== undefined && { rekorPubPem: readFileSync(values['rekor-key'], 'utf8') }),
  });
  if (values.json) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    process.stdout.write(renderReport(report) + '\n');
    if (report.auditPacket) {
      process.stdout.write('\naudit-packet.json:\n' + JSON.stringify(report.auditPacket, null, 2) + '\n');
    }
  }
  process.exit(report.exitCode);
}

async function cmdReplay(argv: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: { session: { type: 'string' }, json: { type: 'boolean', default: false } },
  });
  const dir = positionals[0] ?? defaultLedgerDir();
  const path = existsSync(join(dir, 'ledger.jsonl')) ? join(dir, 'ledger.jsonl') : join(dir, 'ledger', 'entries.jsonl');
  if (!existsSync(path)) fail(`no ledger at ${dir}`);
  const entries = readEntries(path).filter(
    (e) => values.session === undefined || e.session_id === values.session,
  );
  // Pair within a session: proxy call_ids are JSON-RPC ids that restart at 1
  // every session, so a bare call_id would pair across sessions.
  const requests = new Map<string, LedgerEntry>();
  const pairKey = (e: LedgerEntry): string => `${e.session_id} ${e.call_id}`;
  for (const e of entries) {
    if (e.type === 'call_request' && e.call_id !== undefined) requests.set(pairKey(e), e);
  }
  for (const e of entries) {
    if (e.type !== 'call_result' || e.call_id === undefined) continue;
    const req = requests.get(pairKey(e));
    if (!req) continue;
    const durationMs = Date.parse(e.ts) - Date.parse(req.ts);
    const show = (entry: LedgerEntry) =>
      entry.payload === undefined ? `[REDACTED payload_hash=${entry.payload_hash.slice(0, 16)}…]` : entry.payload;
    const status = e.payload?.includes('"error"') || e.payload?.includes('"isError":true') ? 'error' : 'ok';
    if (values.json) {
      process.stdout.write(
        JSON.stringify({
          call_id: e.call_id,
          tool: req.tool,
          session_id: e.session_id,
          request_ts: req.ts,
          duration_ms: durationMs,
          status,
          request: req.payload !== undefined ? JSON.parse(req.payload) : null,
          result: e.payload !== undefined ? JSON.parse(e.payload) : null,
          redacted: req.payload === undefined || e.payload === undefined,
        }) + '\n',
      );
    } else {
      process.stdout.write(
        `[${req.ts}] ${req.tool?.name ?? '?'} (${e.call_id}) ${status} ${durationMs}ms\n  → ${show(req)}\n  ← ${show(e)}\n`,
      );
    }
  }
}

// placeholders replaced as components land
async function cmdExport(argv: string[]): Promise<void> {
  const { runExport } = await import('./export.ts');
  await runExport(argv);
}

async function cmdRedact(argv: string[]): Promise<void> {
  const { runRedact } = await import('./redact.ts');
  await runRedact(argv);
}

async function cmdDemo(argv: string[]): Promise<void> {
  const { runDemo } = await import('./demo.ts');
  await runDemo(argv);
}

// ---------------- dispatch ----------------

const [cmd, ...rest] = process.argv.slice(2);
try {
  switch (cmd) {
    case 'keys':
      await cmdKeys(rest);
      break;
    case 'wrap':
      await cmdWrap(rest);
      break;
    case 'install':
      await cmdInstall(rest);
      break;
    case 'verify':
      await cmdVerify(rest);
      break;
    case 'export':
      await cmdExport(rest);
      break;
    case 'redact':
      await cmdRedact(rest);
      break;
    case 'replay':
      await cmdReplay(rest);
      break;
    case 'demo':
      await cmdDemo(rest);
      break;
    case undefined:
    case 'help':
    case '--help':
    case '-h':
      process.stdout.write(USAGE + '\n');
      break;
    default:
      fail(`unknown command: ${cmd}\n\n${USAGE}`);
  }
} catch (err) {
  fail((err as Error).message);
}
