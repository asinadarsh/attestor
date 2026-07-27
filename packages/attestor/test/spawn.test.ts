// Windows launch behavior, tested from any platform: planSpawn is pure and
// takes the platform as a parameter, so the cmd.exe path is covered on Linux
// CI too. Escaping is checked against cross-spawn, the implementation the MCP
// SDK itself uses — if these diverge, a wrapped server would launch
// differently from an unwrapped one.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, chmodSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { escapeArgument, escapeCommand, planSpawn, resolveCommand } from '../src/spawn.ts';

const require = createRequire(import.meta.url);

test('escaping matches cross-spawn exactly (the MCP SDK uses it)', () => {
  const ref = require('cross-spawn/lib/util/escape.js') as {
    command: (a: string) => string;
    argument: (a: string, d?: boolean) => string;
  };
  const cases = [
    'simple',
    'with space',
    'quote"inside',
    'trailing\\',
    'back\\\\slashes',
    'meta&chars|here',
    'semi;colon,comma',
    'paren(s)[brackets]',
    'percent%var%',
    'caret^and!bang',
    'star*question?',
    '',
    'C:\\Program Files\\nodejs\\node.exe',
    '{"json":"payload with spaces & pipes|"}',
  ];
  for (const c of cases) {
    assert.equal(escapeArgument(c), ref.argument(c), `argument: ${JSON.stringify(c)}`);
    assert.equal(escapeArgument(c, true), ref.argument(c, true), `argument x2: ${JSON.stringify(c)}`);
    assert.equal(escapeCommand(c), ref.command(c), `command: ${JSON.stringify(c)}`);
  }
});

test('non-Windows: command is spawned directly, untouched', () => {
  const plan = planSpawn('npx', ['-y', '@modelcontextprotocol/server-github'], 'linux');
  assert.equal(plan.command, 'npx');
  assert.deepEqual(plan.args, ['-y', '@modelcontextprotocol/server-github']);
  assert.equal(plan.windowsVerbatimArguments, false);
});

test('Windows: a .cmd shim is launched through cmd.exe with verbatim args', () => {
  const dir = mkdtempSync(join(tmpdir(), 'attestor-spawn-'));
  writeFileSync(join(dir, 'npx.cmd'), '@echo off\n');
  const env = { PATH: dir, PATHEXT: '.COM;.EXE;.BAT;.CMD', ComSpec: 'C:\\Windows\\system32\\cmd.exe' };

  const plan = planSpawn('npx', ['-y', 'server-github'], 'win32', env);
  assert.equal(plan.command, 'C:\\Windows\\system32\\cmd.exe');
  assert.equal(plan.windowsVerbatimArguments, true, 'args are pre-escaped, Node must not re-quote them');
  assert.equal(plan.args[0], '/d');
  assert.equal(plan.args[1], '/s');
  assert.equal(plan.args[2], '/c');
  assert.match(plan.args[3]!, /^".*"$/, 'whole command line is wrapped in quotes');
  assert.ok(plan.args[3]!.includes('npx'));
  // On case-insensitive filesystems (Windows, default macOS) the probe may
  // match npx.cmd via the uppercase PATHEXT entry, so compare case-insensitively.
  assert.ok(plan.resolved?.toLowerCase().endsWith('npx.cmd'), `resolved: ${plan.resolved}`);
});

test('Windows: a real .exe is spawned directly, no shell involved', () => {
  const dir = mkdtempSync(join(tmpdir(), 'attestor-spawn-'));
  writeFileSync(join(dir, 'node.exe'), '');
  const env = { PATH: dir, PATHEXT: '.COM;.EXE;.BAT;.CMD' };
  const plan = planSpawn('node', ['server.js'], 'win32', env);
  assert.equal(plan.command, 'node');
  assert.deepEqual(plan.args, ['server.js']);
  assert.equal(plan.windowsVerbatimArguments, false);
});

test('Windows: shell metacharacters in args cannot break out of the command line', () => {
  const dir = mkdtempSync(join(tmpdir(), 'attestor-spawn-'));
  writeFileSync(join(dir, 'npx.cmd'), '@echo off\n');
  const env = { PATH: dir, PATHEXT: '.CMD', ComSpec: 'cmd.exe' };
  // a malicious server name / argument
  const evil = 'x" & calc.exe & echo "';
  const plan = planSpawn('npx', [evil], 'win32', env);
  const line = plan.args[3]!;
  // every metacharacter that could start a new command must be ^-escaped
  for (const m of ['&', '|']) {
    const bare = new RegExp(`(?<!\\^)\\${m}`);
    assert.ok(!bare.test(line), `unescaped ${m} in: ${line}`);
  }
  assert.ok(line.includes('^&'), 'ampersand is neutralized');
});

test('Windows: node_modules/.bin shims get double-escaped args', () => {
  const dir = mkdtempSync(join(tmpdir(), 'attestor-spawn-'));
  const binDir = join(dir, 'node_modules', '.bin');
  mkdirSync(binDir, { recursive: true });
  writeFileSync(join(binDir, 'server.cmd'), '@echo off\n');
  const env = { PATH: binDir, PATHEXT: '.CMD', ComSpec: 'cmd.exe' };
  const plan = planSpawn('server', ['a&b'], 'win32', env);
  assert.ok(plan.args[3]!.includes('^^^&'), `expected double escape, got: ${plan.args[3]}`);
});

test('Windows: an unresolvable command is left alone so Node reports ENOENT', () => {
  const env = { PATH: mkdtempSync(join(tmpdir(), 'attestor-empty-')), PATHEXT: '.CMD', ComSpec: 'cmd.exe' };
  const plan = planSpawn('definitely-not-installed', ['x'], 'win32', env);
  // still routed through cmd (it may be a shell builtin), but never crashes
  assert.ok(plan.command === 'cmd.exe' || plan.command === 'definitely-not-installed');
  assert.equal(plan.resolved, undefined);
});

test('resolveCommand honors PATHEXT order and finds POSIX executables', () => {
  const dir = mkdtempSync(join(tmpdir(), 'attestor-resolve-'));
  writeFileSync(join(dir, 'tool.CMD'), '');
  writeFileSync(join(dir, 'tool.EXE'), '');
  // .EXE comes before .CMD in PATHEXT, so it must win
  const winEnv = { PATH: dir, PATHEXT: '.COM;.EXE;.BAT;.CMD' };
  assert.ok(resolveCommand('tool', winEnv, 'win32')?.toLowerCase().endsWith('.exe'));

  const posix = join(dir, 'posixtool');
  writeFileSync(posix, '#!/bin/sh\n');
  chmodSync(posix, 0o755);
  assert.equal(resolveCommand('posixtool', { PATH: dir }, 'linux'), posix);
  assert.equal(resolveCommand('nope', { PATH: dir }, 'linux'), undefined);
});

test('Windows: arguments containing a newline or NUL are refused, not mangled', () => {
  const dir = mkdtempSync(join(tmpdir(), 'attestor-spawn-'));
  writeFileSync(join(dir, 'npx.cmd'), '@echo off\n');
  const env = { PATH: dir, PATHEXT: '.CMD', ComSpec: 'cmd.exe' };
  // CR/LF/NUL cannot be escaped for cmd.exe under any quoting scheme, so the
  // only safe handling is refusal.
  for (const evil of ['a\ncalc.exe', 'a\r\ncalc.exe', 'a\0b']) {
    assert.throws(
      () => planSpawn('npx', [evil], 'win32', env),
      /cannot be escaped for cmd\.exe/,
      `must refuse: ${JSON.stringify(evil)}`,
    );
  }
  // …and they are fine everywhere else, where no shell is involved
  assert.doesNotThrow(() => planSpawn('npx', ['a\nb'], 'linux', env));
});

// ---- real-Windows tests: these exercise the code paths that only exist on
// Windows, and are the reason windows-latest is in the CI matrix. Everything
// above is simulated (planSpawn takes the platform as a parameter); these are
// not, so they skip elsewhere.

const onlyWindows = { skip: process.platform !== 'win32' ? 'windows-only' : false };

test('Windows: a real .cmd server is launched through cmd.exe and relays byte-exactly', onlyWindows, async () => {
  const { Ledger, readEntries } = await import('../src/ledger.ts');
  const { Checkpointer } = await import('../src/checkpoint.ts');
  const { runProxy } = await import('../src/proxy.ts');
  const { generateKey } = await import('../src/keys.ts');
  const { PassThrough } = await import('node:stream');
  const { setTimeout: sleep } = await import('node:timers/promises');
  const { dirname } = await import('node:path');
  const { fileURLToPath } = await import('node:url');

  const here = dirname(fileURLToPath(import.meta.url));
  const toy = join(here, '..', '..', 'toy-mcp-server', 'server.js');
  const dir = mkdtempSync(join(tmpdir(), 'attestor-cmd-'));

  // a .cmd shim, exactly the shape `npx` and every npm global bin uses —
  // spawning this directly is what Node refuses to do (CVE-2024-27980).
  const shim = join(dir, 'toy-server.cmd');
  writeFileSync(shim, `@echo off\r\n"${process.execPath}" "${toy}" %*\r\n`);

  const keys = generateKey(join(dir, 'home'));
  const ledger = Ledger.open(join(dir, 'ledger'), keys);
  const ckpt = new Checkpointer(ledger, { idleMs: 3600_000 });
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const chunks: Buffer[] = [];
  stdout.on('data', (c: Buffer) => chunks.push(c));

  const done = runProxy({
    ledger,
    checkpointer: ckpt,
    command: shim,
    args: [],
    stdin,
    stdout,
    stderr: new PassThrough(),
  });
  stdin.write('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"через cmd"}}}\n');
  await sleep(3000);
  stdin.end();
  await done;
  ledger.close();

  const out = Buffer.concat(chunks).toString('utf8');
  assert.match(out, /через cmd/, `server reply must come back through cmd.exe, got: ${out}`);

  const entries = readEntries(join(dir, 'ledger', 'ledger.jsonl'));
  assert.ok(entries.some((e) => e.type === 'call_request' && e.payload?.includes('через cmd')));
  assert.ok(entries.some((e) => e.type === 'call_result' && e.payload?.includes('через cmd')));
});

test('Windows: the signing key ACL is actually restricted to this user', onlyWindows, async () => {
  const { generateKey, protectKeyFile } = await import('../src/keys.ts');
  const { spawnSync } = await import('node:child_process');

  const dir = mkdtempSync(join(tmpdir(), 'attestor-acl-'));
  const keys = generateKey(join(dir, 'home'));
  const keyPath = join(dir, 'home', 'keys', `${keys.keyId}.pem`);

  const result = protectKeyFile(keyPath);
  assert.equal(result.protected, true, `icacls must succeed on CI: ${result.detail}`);

  // Ask Windows what the ACL actually is, rather than trusting our exit code.
  const acl = spawnSync('icacls', [keyPath], { encoding: 'utf8' });
  assert.equal(acl.status, 0, acl.stderr);
  const listing = acl.stdout;
  // The whole point: no broad principal may still be able to read the key.
  for (const broad of ['BUILTIN\\Users', 'Everyone', 'AUTHENTICATED USERS']) {
    assert.ok(
      !new RegExp(broad.replace(/\\/g, '\\\\'), 'i').test(listing),
      `${broad} must not have access to the signing key:\n${listing}`,
    );
  }
  assert.match(listing, new RegExp(process.env.USERNAME ?? 'nobody', 'i'), `owner must retain access:\n${listing}`);
});
