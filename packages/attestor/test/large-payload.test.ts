// A large payload (bigger than a typical pipe buffer) must be written whole —
// a short write would leave a torn line mid-ledger and read as tamper.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { generateKey } from '../src/keys.ts';
import { Ledger, readEntries } from '../src/ledger.ts';
import { verifyLedger } from '../src/verify.ts';
import { tmp } from './helpers.ts';

test('multi-megabyte payload round-trips and verifies', async () => {
  const dir = tmp();
  const keys = generateKey(join(dir, 'home'));
  const ledger = Ledger.open(join(dir, 'ledger'), keys);
  const big = JSON.stringify({ blob: 'x'.repeat(4 * 1024 * 1024) });
  ledger.append({ type: 'call_result', origin: 'sdk', payload: big });
  ledger.append({ type: 'wire', origin: 'proxy', payload: '"after"' });
  ledger.close();

  const entries = readEntries(join(dir, 'ledger', 'ledger.jsonl'));
  assert.equal(entries[1]!.payload, big);
  assert.equal(entries[2]!.payload, '"after"');
  const report = await verifyLedger(join(dir, 'ledger'));
  assert.equal(report.exitCode, 0, JSON.stringify(report.findings));
});
