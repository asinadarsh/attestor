// Repro for orphan-anchor sweep claim.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { verifyLedger } from '../src/verify.ts';
import { coreOf, hashCore, signCore, genesisPrev, payloadHash, type LedgerEntry } from '../src/ledger.ts';
import { keyIdOf } from '../src/keys.ts';
import { merkleRoot } from '../src/merkle.ts';
import { buildAnchoredLedger } from './helpers.ts';

function readLines(dir: string): string[] {
  return readFileSync(join(dir, 'ledger.jsonl'), 'utf8').trimEnd().split('\n');
}
function writeLines(dir: string, lines: string[]): void {
  writeFileSync(join(dir, 'ledger.jsonl'), lines.join('\n') + '\n');
}

test('CLAIM: rewrite history + delete anchor entry only, keep anchors/13.json', async () => {
  const { ledgerDir, ledgerId } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  console.log('entry count:', lines.length);
  const entries = lines.map((l) => JSON.parse(l) as LedgerEntry);
  console.log('types:', entries.map((e) => `${e.seq}:${e.type}`).join(' '));
  assert.ok(existsSync(join(ledgerDir, 'anchors', '13.json')), 'anchors/13.json exists');

  const atk = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const atkPem = atk.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const atkKeyId = keyIdOf(atk.publicKey);

  // Rewrite EVERY entry consistently, then drop ONLY the last (anchor) line.
  let prev = genesisPrev(ledgerId);
  const rewritten: string[] = [];
  const newHashes: string[] = [];
  for (const e of entries) {
    if (e.type === 'anchor') continue; // <-- delete only the anchor entry
    if (e.type === 'genesis') {
      e.payload = JSON.stringify({ ledger_id: ledgerId, public_key_pem: atkPem, attestor_version: 1 });
    }
    if (e.payload?.includes('100.00')) {
      e.payload = e.payload.replace('100.00', '100000.00');
    }
    if (e.type === 'checkpoint') {
      const payload = JSON.parse(e.payload!) as { ledger_id: string; tree_size: number; root: string };
      payload.root = merkleRoot(newHashes.slice(0, payload.tree_size).map((h) => Buffer.from(h, 'hex'))).toString('hex');
      e.payload = JSON.stringify(payload);
    }
    e.key_id = atkKeyId;
    e.prev = prev;
    e.salt = createHash('sha256').update(e.hash).digest('hex').slice(0, 32);
    e.payload_hash = payloadHash(e.salt, e.payload);
    const core = coreOf(e as unknown as Record<string, unknown>);
    e.hash = hashCore(core);
    e.sig = signCore(core, atk.privateKey);
    prev = e.hash;
    newHashes.push(e.hash);
    rewritten.push(JSON.stringify(e));
  }
  writeLines(ledgerDir, rewritten);

  const offline = await verifyLedger(ledgerDir);
  console.log('OFFLINE result:', offline.result, 'exit', offline.exitCode);
  console.log('checks:', offline.checks.map((c) => `${c.name}:${c.ok ? 'ok' : 'FAIL'}`).join(' '));
  console.log('ANCHOR lines:', JSON.stringify(offline.checks.find((c) => c.name === 'ANCHOR')?.lines));
  console.log('findings:', JSON.stringify(offline.findings));

  const online = await verifyLedger(ledgerDir, { online: true });
  console.log('ONLINE result:', online.result, 'exit', online.exitCode);

  // If the claim is CORRECT, exit is 0 (vulnerability). If a check catches it, exit is 1.
  console.log('>>> VULNERABLE?', offline.exitCode === 0);
});
