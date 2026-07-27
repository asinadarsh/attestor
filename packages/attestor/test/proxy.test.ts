// Proxy tests: a real @modelcontextprotocol/sdk Client through the actual
// `attestor wrap` CLI against toy-mcp-server (transparency), plus in-process
// runProxy with injected ledger failures (block/-32000, continue/gap markers).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { existsSync } from 'node:fs';
import { join, dirname, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { generateKey } from '../src/keys.ts';
import { Ledger, readEntries } from '../src/ledger.ts';
import { Checkpointer } from '../src/checkpoint.ts';
import { classifyLine, lineSplitter, runProxy } from '../src/proxy.ts';
import { verifyLedger } from '../src/verify.ts';
import { tmp } from './helpers.ts';

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'src', 'cli.ts');
const TOY = join(here, '..', '..', 'toy-mcp-server', 'server.js');

test('real MCP client through attestor wrap: transparent relay + complete record', async () => {
  const dir = tmp();
  const home = join(dir, 'home');
  const ledgerDir = join(dir, 'ledger');
  generateKey(home);

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [CLI, 'wrap', '--ledger', ledgerDir, '--offline', '--', process.execPath, TOY],
    env: { ...(process.env as Record<string, string>), ATTESTOR_HOME: home },
    stderr: 'pipe',
  });
  const client = new Client({ name: 'attestor-test-client', version: '1.0.0' });
  await client.connect(transport);

  const tools = await client.listTools();
  assert.equal(tools.tools.length, 1);
  assert.equal(tools.tools[0]!.name, 'echo');

  const result = (await client.callTool({ name: 'echo', arguments: { text: 'hello attestor' } })) as {
    content: { type: string; text: string }[];
  };
  assert.equal(result.content[0]!.text, 'hello attestor');

  await client.close();
  await sleep(400); // wrap process finalizes session_end + checkpoint

  const entries = readEntries(join(ledgerDir, 'ledger.jsonl'));
  const types = entries.map((e) => e.type);
  assert.equal(types[0], 'genesis');
  assert.ok(types.includes('session_start'));
  assert.ok(types.includes('call_request'));
  assert.ok(types.includes('call_result'));
  assert.ok(types.includes('session_end'));
  assert.ok(types.includes('checkpoint'));

  const req = entries.find((e) => e.type === 'call_request')!;
  assert.equal(req.direction, 'c2s');
  assert.equal(req.tool?.name, 'echo');
  assert.ok(req.payload!.includes('hello attestor'));
  const res = entries.find((e) => e.type === 'call_result')!;
  assert.equal(res.direction, 's2c');
  assert.equal(res.call_id, req.call_id);
  assert.ok(res.payload!.includes('hello attestor'));

  // initialize exchange + notifications recorded as wire entries
  const wires = entries.filter((e) => e.type === 'wire');
  assert.ok(wires.some((e) => e.payload?.includes('"initialize"')));
  assert.ok(wires.some((e) => e.payload?.includes('notifications/initialized')));

  // the record verifies end-to-end
  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 0, JSON.stringify(report.findings));
});

test('child exit code propagates through wrap', async () => {
  const dir = tmp();
  const keys = generateKey(join(dir, 'home'));
  const ledger = Ledger.open(join(dir, 'ledger'), keys);
  const ckpt = new Checkpointer(ledger, { idleMs: 3600_000 });
  const stdin = new PassThrough();
  const code = await runProxy({
    ledger,
    checkpointer: ckpt,
    command: process.execPath,
    args: ['-e', 'process.exit(7)'],
    stdin,
    stdout: new PassThrough(),
    stderr: new PassThrough(),
  });
  assert.equal(code, 7);
  ledger.close();
});

test('unparsable line: relayed verbatim AND recorded as wire', async () => {
  const dir = tmp();
  const keys = generateKey(join(dir, 'home'));
  const ledger = Ledger.open(join(dir, 'ledger'), keys);
  const ckpt = new Checkpointer(ledger, { idleMs: 3600_000 });
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  // child echoes its stdin to stdout verbatim (cat)
  const done = runProxy({
    ledger,
    checkpointer: ckpt,
    command: process.execPath,
    args: ['-e', 'process.stdin.pipe(process.stdout)'],
    stdin,
    stdout,
    stderr: new PassThrough(),
  });
  const garbage = 'this is {not json\n';
  stdin.write(garbage);
  await sleep(200);
  stdin.end();
  await done;
  ledger.close();

  const out = stdout.read()?.toString() ?? '';
  assert.ok(out.includes('this is {not json'), 'garbage relayed');
  const entries = readEntries(join(dir, 'ledger', 'ledger.jsonl'));
  const wire = entries.find((e) => e.payload === 'this is {not json');
  assert.ok(wire, 'garbage recorded');
  assert.equal(wire.type, 'wire');
});

test('block mode: unwritable ledger → synthesized -32000, no forward, no hang', async () => {
  const dir = tmp();
  const keys = generateKey(join(dir, 'home'));
  const ledger = Ledger.open(join(dir, 'ledger'), keys);
  const ckpt = new Checkpointer(ledger, { idleMs: 3600_000 });
  const stdin = new PassThrough();
  const stdout = new PassThrough();

  const realAppend = ledger.append.bind(ledger);
  let broken = false;
  (ledger as { append: typeof ledger.append }).append = (input, s) => {
    if (broken) throw new Error('disk full (injected)');
    return realAppend(input, s);
  };

  const done = runProxy({
    ledger,
    checkpointer: ckpt,
    command: process.execPath,
    args: ['-e', 'process.stdin.pipe(process.stdout)'], // echo child: would reply if forwarded
    onError: 'block',
    stdin,
    stdout,
    stderr: new PassThrough(),
  });

  broken = true;
  stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 42, method: 'tools/call', params: { name: 'echo', arguments: {} } }) + '\n');
  await sleep(200);
  const out = stdout.read()?.toString() ?? '';
  assert.ok(out.includes('-32000'), `expected synthesized error, got: ${out}`);
  assert.ok(out.includes('"id":42'));
  assert.ok(!out.includes('"method":"tools/call"'), 'request must NOT be forwarded (echo child saw nothing)');

  broken = false;
  stdin.end();
  await done;
  ledger.close();
});

test('continue mode: traffic relayed during outage, signed gap marker on recovery', async () => {
  const dir = tmp();
  const keys = generateKey(join(dir, 'home'));
  const ledger = Ledger.open(join(dir, 'ledger'), keys);
  const ckpt = new Checkpointer(ledger, { idleMs: 3600_000 });
  const stdin = new PassThrough();
  const stdout = new PassThrough();

  const realAppend = ledger.append.bind(ledger);
  let broken = false;
  (ledger as { append: typeof ledger.append }).append = (input, s) => {
    if (broken) throw new Error('disk full (injected)');
    return realAppend(input, s);
  };

  const done = runProxy({
    ledger,
    checkpointer: ckpt,
    command: process.execPath,
    args: ['-e', 'process.stdin.pipe(process.stdout)'],
    onError: 'continue',
    stdin,
    stdout,
    stderr: new PassThrough(),
  });

  broken = true;
  stdin.write('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}\n');
  stdin.write('{"jsonrpc":"2.0","method":"notifications/progress"}\n');
  await sleep(150);
  const out = stdout.read()?.toString() ?? '';
  assert.ok(out.includes('tools/call'), 'continue mode still relays during outage');

  broken = false;
  stdin.write('{"jsonrpc":"2.0","id":2,"method":"ping"}\n');
  await sleep(150);
  stdin.end();
  await done;
  ledger.close();

  const entries = readEntries(join(dir, 'ledger', 'ledger.jsonl'));
  const gap = entries.find((e) => e.type === 'gap');
  assert.ok(gap, 'gap marker appended on recovery');
  // 2 c2s lines + their s2c echoes all fell in the outage window
  const gapPayload = JSON.parse(gap.payload!) as { unrecorded_lines: number };
  assert.ok(gapPayload.unrecorded_lines >= 2, `gap counted ${gapPayload.unrecorded_lines}`);
  // the gap marker itself is chained + signed like everything else
  const report = await verifyLedger(join(dir, 'ledger'));
  assert.equal(report.exitCode, 0);
});

test('lineSplitter preserves exact bytes across chunk boundaries', () => {
  const lines: string[] = [];
  const feed = lineSplitter((l) => lines.push(l.toString('utf8')));
  feed(Buffer.from('{"a":'));
  feed(Buffer.from('1}\n{"b":2}\n{"c"'));
  feed(Buffer.from(':3}\n'));
  assert.deepEqual(lines, ['{"a":1}', '{"b":2}', '{"c":3}']);
});

test('classifyLine: request/response/notification/unparsed', () => {
  assert.equal(classifyLine(Buffer.from('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t"}}')).toolName, 't');
  assert.equal(classifyLine(Buffer.from('{"jsonrpc":"2.0","method":"notifications/x"}')).kind, 'notification');
  assert.equal(classifyLine(Buffer.from('{"jsonrpc":"2.0","id":1,"result":{}}')).kind, 'response');
  assert.equal(classifyLine(Buffer.from('{"jsonrpc":"2.0","id":1,"error":{"code":1}}')).isError, true);
  assert.equal(classifyLine(Buffer.from('garbage')).kind, 'unparsed');
  assert.equal(classifyLine(Buffer.from('123')).kind, 'unparsed');
});

test('install gives each server its own ledger so concurrent servers do not deadlock', async () => {
  const { wrapConfig } = await import('../src/cli.ts');
  const inv = { command: 'attestor', prefixArgs: [] as string[] };
  const config = {
    mcpServers: {
      github: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'] },
      'My Files!': { command: 'node', args: ['files.js'] },
    },
  };
  const { changed } = wrapConfig(config, inv);
  assert.deepEqual(changed, ['github', 'My Files!']);
  const names = Object.values(config.mcpServers).map((d) => {
    const i = d.args!.indexOf('--ledger-name');
    return d.args![i + 1];
  });
  assert.deepEqual(names, ['github', 'my-files']);
  assert.equal(new Set(names).size, names.length, 'ledger dirs must be distinct');

  // idempotent across spellings
  const again = wrapConfig(config, inv);
  assert.deepEqual(again.changed, []);
  const npxStyle = { mcpServers: { a: { command: 'npx', args: ['attestor', 'wrap', '--', 'node', 's.js'] } } };
  assert.deepEqual(wrapConfig(npxStyle, inv).changed, [], 'npx attestor wrap already counts as wrapped');
});

test('unterminated final line is relayed AND recorded, not dropped', async () => {
  const dir = tmp();
  const keys = generateKey(join(dir, 'home'));
  const ledger = Ledger.open(join(dir, 'ledger'), keys);
  const ckpt = new Checkpointer(ledger, { idleMs: 3600_000 });
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const done = runProxy({
    ledger,
    checkpointer: ckpt,
    command: process.execPath,
    args: ['-e', 'process.stdin.pipe(process.stdout)'],
    stdin,
    stdout,
    stderr: new PassThrough(),
  });
  stdin.write('{"jsonrpc":"2.0","id":1,"method":"ping"}'); // NO trailing newline
  await sleep(120);
  stdin.end();
  await done;
  ledger.close();

  const entries = readEntries(join(dir, 'ledger', 'ledger.jsonl'));
  assert.ok(
    entries.some((e) => e.payload === '{"jsonrpc":"2.0","id":1,"method":"ping"}'),
    'unterminated tail must still reach the ledger',
  );
});

test('gap survives a process that never recovers: pending note folded in on next open', async () => {
  const dir = tmp();
  const keys = generateKey(join(dir, 'home'));
  const ledgerDir = join(dir, 'ledger');
  const ledger = Ledger.open(ledgerDir, keys);
  const ckpt = new Checkpointer(ledger, { idleMs: 3600_000 });
  const realAppend = ledger.append.bind(ledger);
  (ledger as { append: typeof ledger.append }).append = () => {
    throw new Error('disk full (injected)');
  };
  const stdin = new PassThrough();
  const done = runProxy({
    ledger,
    checkpointer: ckpt,
    command: process.execPath,
    args: ['-e', 'process.stdin.pipe(process.stdout)'],
    onError: 'continue',
    stdin,
    stdout: new PassThrough(),
    stderr: new PassThrough(),
  });
  stdin.write('{"jsonrpc":"2.0","id":1,"method":"ping"}\n');
  await sleep(120);
  stdin.end();
  await done;
  (ledger as { append: typeof ledger.append }).append = realAppend;
  ledger.close();

  // next successful open must fold the hole into the signed chain
  const reopened = Ledger.open(ledgerDir, keys);
  reopened.close();
  const entries = readEntries(join(ledgerDir, 'ledger.jsonl'));
  assert.ok(entries.some((e) => e.type === 'gap'), 'unrecovered gap must not vanish silently');
  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 0, JSON.stringify(report.findings));
});

test('install writes a command that actually resolves when attestor is not on PATH', async () => {
  const { wrapConfig, attestorInvocation } = await import('../src/cli.ts');
  const config = { mcpServers: { toy: { command: 'node', args: ['server.js'] } } };
  wrapConfig(config, attestorInvocation());
  const def = config.mcpServers.toy;

  // whatever we wrote must be launchable as-is: either `attestor` on PATH, or
  // an absolute interpreter + script path.
  if (def.command !== 'attestor') {
    assert.ok(isAbsolute(def.command), `command must be absolute, got ${def.command}`);
    assert.ok(existsSync(def.command), `command must exist: ${def.command}`);
    const script = def.args![0]!;
    assert.ok(isAbsolute(script) && existsSync(script), `cli path must exist: ${script}`);
    assert.equal(def.args![1], 'wrap');
  }
  // and re-running install must not double-wrap it
  assert.deepEqual(wrapConfig(config, attestorInvocation()).changed, []);
});

test('Claude Desktop config path is correct for each platform', async () => {
  const { claudeDesktopConfigPaths } = await import('../src/cli.ts');
  const paths = claudeDesktopConfigPaths();
  assert.ok(paths.length > 0);
  for (const p of paths) assert.ok(isAbsolute(p), `${p} must be absolute`);
  assert.ok(paths.every((p) => p.endsWith('claude_desktop_config.json')));
  // the current platform's path must not be some other platform's convention
  const p0 = paths[0]!;
  if (process.platform === 'win32') assert.ok(/AppData|APPDATA/i.test(p0) || /Claude/.test(p0));
  else if (process.platform === 'darwin') assert.ok(p0.includes('Library/Application Support'));
  else assert.ok(p0.includes('.config') || p0.includes('Claude'));
});
