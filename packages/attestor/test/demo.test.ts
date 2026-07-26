// E2E: `attestor demo tamper --offline` — green verify (exit 0 shown), then
// TAMPER DETECTED (exit 1 shown), then the full-rewrite kicker also caught.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmp } from './helpers.ts';

const exec = promisify(execFile);
const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'cli.ts');

test('demo tamper --offline: green → red → kicker, correct exit codes shown', async () => {
  const home = tmp('attestor-demo-home-');
  const { stdout } = await exec(process.execPath, [CLI, 'demo', 'tamper', '--offline'], {
    env: { ...process.env, ATTESTOR_HOME: home, ATTESTOR_OFFLINE: '1' },
    timeout: 60_000,
  });

  // phase order: green pass, then tamper detected, then kicker caught
  const greenAt = stdout.indexOf('RESULT: VERIFIED  (exit 0)');
  const redAt = stdout.indexOf('RESULT: TAMPER DETECTED  (exit 1)');
  assert.ok(greenAt !== -1, 'green verify block present');
  assert.ok(redAt > greenAt, 'tamper block after green block');
  assert.ok(stdout.includes('100000.00'), 'shows the attacker edit');
  assert.ok(stdout.includes('audit-packet.json'), 'audit packet emitted');
  assert.ok(stdout.includes('SIMULATED'), 'offline mode says so honestly');
  assert.ok(stdout.includes('re-signs EVERYTHING'), 'kicker narrative present');
  const lastTamper = stdout.lastIndexOf('RESULT: TAMPER DETECTED  (exit 1)');
  assert.ok(lastTamper > redAt, 'kicker rewrite also detected');
  assert.ok(stdout.includes('blast radius'), 'blast radius reported');
});
