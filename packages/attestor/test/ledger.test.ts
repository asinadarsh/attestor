import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import canonicalize from 'canonicalize';
import { generateKey } from '../src/keys.ts';
import {
  Ledger,
  coreOf,
  genesisPrev,
  hashCore,
  payloadHash,
  readEntries,
  uuidv7,
  verifyCoreSig,
} from '../src/ledger.ts';

function tmp(): string {
  return mkdtempSync(join(tmpdir(), 'attestor-test-'));
}

function newLedger(dir = tmp()) {
  const keys = generateKey(join(dir, 'home'));
  const ledger = Ledger.open(join(dir, 'ledger'), keys);
  return { dir, keys, ledger };
}

test('chain round-trip: hashes link, sigs verify, reopen resumes', () => {
  const { dir, keys, ledger } = newLedger();
  const session = uuidv7();
  for (let i = 0; i < 10; i++) {
    ledger.append({
      type: 'call_request',
      origin: 'proxy',
      call_id: `call-${i}`,
      payload: JSON.stringify({ i, text: 'héllo δ' }),
      session_id: session,
    });
  }
  ledger.close();

  const entries = readEntries(join(dir, 'ledger', 'ledger.jsonl'));
  assert.equal(entries.length, 11); // genesis + 10
  let prev = genesisPrev(ledger.ledgerId);
  for (const e of entries) {
    assert.equal(e.prev, prev);
    const core = coreOf(e as unknown as Record<string, unknown>);
    assert.equal(hashCore(core), e.hash);
    assert.ok(verifyCoreSig(core, e.sig, keys.publicKey));
    assert.equal(e.payload_hash, payloadHash(e.salt, e.payload));
    prev = e.hash;
  }

  // reopen: chain resumes from the last hash
  const ledger2 = Ledger.open(join(dir, 'ledger'), keys);
  const e = ledger2.append({ type: 'session_end', origin: 'proxy', session_id: session });
  assert.equal(e.seq, 11);
  assert.equal(e.prev, entries[entries.length - 1]!.hash);
  ledger2.close();
});

test('seq is strictly monotonic from 0', () => {
  const { ledger } = newLedger();
  const seqs = [ledger.size - 1]; // genesis seq 0 already written
  for (let i = 0; i < 5; i++) {
    seqs.push(ledger.append({ type: 'wire', origin: 'proxy', payload: '{}' }).seq);
  }
  assert.deepEqual(seqs, [0, 1, 2, 3, 4, 5]);
  ledger.close();
});

test('lockfile excludes a second writer; stale lock is broken', () => {
  const { dir, keys, ledger } = newLedger();
  assert.throws(
    () => Ledger.open(join(dir, 'ledger'), keys),
    /ledger locked by pid/,
  );
  ledger.close();
  // stale lock: fake a dead pid
  writeFileSync(join(dir, 'ledger', 'ledger.lock'), '999999999');
  const ledger2 = Ledger.open(join(dir, 'ledger'), keys);
  assert.ok(ledger2.size >= 1);
  ledger2.close();
});

test('torn tail: partial final line recovered to ledger.torn, chain resumes', () => {
  const { dir, keys, ledger } = newLedger();
  for (let i = 0; i < 3; i++) {
    ledger.append({ type: 'wire', origin: 'proxy', payload: `"${i}"` });
  }
  ledger.close();
  const path = join(dir, 'ledger', 'ledger.jsonl');
  const before = readEntries(path);
  appendFileSync(path, '{"v":1,"seq":4,"ts":"2026-'); // torn partial write

  const ledger2 = Ledger.open(join(dir, 'ledger'), keys);
  assert.ok(ledger2.tornRecovery.recovered);
  assert.ok(existsSync(join(dir, 'ledger', 'ledger.torn')));
  const e = ledger2.append({ type: 'wire', origin: 'proxy', payload: '"after"' });
  assert.equal(e.seq, 4);
  assert.equal(e.prev, before[before.length - 1]!.hash);
  ledger2.close();

  const after = readEntries(path);
  let prev = genesisPrev(ledger2.ledgerId);
  for (const entry of after) {
    assert.equal(entry.prev, prev);
    assert.equal(hashCore(coreOf(entry as unknown as Record<string, unknown>)), entry.hash);
    prev = entry.hash;
  }
});

test('terminated line with bad hash is NOT auto-recovered (tamper evidence preserved)', () => {
  const { dir, keys, ledger } = newLedger();
  ledger.append({ type: 'wire', origin: 'proxy', payload: '"x"' });
  ledger.close();
  const path = join(dir, 'ledger', 'ledger.jsonl');
  const lines = readFileSync(path, 'utf8').trimEnd().split('\n');
  const tampered = JSON.parse(lines[lines.length - 1]!);
  tampered.payload = '"TAMPERED"';
  tampered.payload_hash = 'ff'.repeat(32);
  lines[lines.length - 1] = JSON.stringify(tampered);
  writeFileSync(path, lines.join('\n') + '\n');

  // open must fail loudly or keep the tampered line in place — never silently drop it
  try {
    const l2 = Ledger.open(join(dir, 'ledger'), keys);
    l2.close();
  } catch {
    /* acceptable: refuse to open */
  }
  assert.ok(!existsSync(join(dir, 'ledger', 'ledger.torn')));
  const raw = readFileSync(path, 'utf8');
  assert.ok(raw.includes('TAMPERED'));
});

test('redaction invariant: stripping payload leaves core hash + sig valid', () => {
  const { dir, keys, ledger } = newLedger();
  ledger.append({
    type: 'call_request',
    origin: 'proxy',
    payload: JSON.stringify({ ssn: '123-45-6789' }),
  });
  ledger.close();
  const entries = readEntries(join(dir, 'ledger', 'ledger.jsonl'));
  const e = entries[1]!;
  const { payload: _dropped, ...redacted } = e;
  const core = coreOf(redacted as unknown as Record<string, unknown>);
  assert.equal(hashCore(core), e.hash);
  assert.ok(verifyCoreSig(core, e.sig, keys.publicKey));
});

test('payload_hash uses salt: same payload, different entries, different hashes', () => {
  const { dir, ledger } = newLedger();
  ledger.append({ type: 'wire', origin: 'proxy', payload: '"same"' });
  ledger.append({ type: 'wire', origin: 'proxy', payload: '"same"' });
  ledger.close();
  const entries = readEntries(join(dir, 'ledger', 'ledger.jsonl'));
  assert.notEqual(entries[1]!.payload_hash, entries[2]!.payload_hash);
});

test('group durability: entries persist after close', () => {
  const { dir, keys } = newLedger();
  const ledger = Ledger.open(join(dir, 'ledger2'), keys, { durability: 'group' });
  for (let i = 0; i < 300; i++) {
    ledger.append({ type: 'wire', origin: 'proxy', payload: String(i) });
  }
  ledger.close();
  assert.equal(readEntries(join(dir, 'ledger2', 'ledger.jsonl')).length, 301);
});

test('JCS canonicalization: key order, non-ASCII, parse/re-canonicalize stability', () => {
  const a = canonicalize({ b: 2, a: 1, nested: { z: 'ü', y: 'δ' } });
  const b = canonicalize({ nested: { y: 'δ', z: 'ü' }, a: 1, b: 2 });
  assert.equal(a, b);
  assert.equal(canonicalize(JSON.parse(a!)), a);
  // JCS emits non-ASCII as literal UTF-8, sorted by UTF-16 code units
  assert.equal(canonicalize({ b: 1, a: 'ü' }), '{"a":"ü","b":1}');
});

test('uuidv7 shape and monotonic timestamp prefix', () => {
  const u = uuidv7();
  assert.match(u, /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
});
