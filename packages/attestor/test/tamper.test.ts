// Tamper matrix: every attack must exit 1 with the correct blast radius;
// redaction must still PASS. Runs the full offline pipeline including ANCHOR
// checks against a simulated Rekor (fake log key pinned at anchors/).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { generateKeyPairSync, sign as cryptoSign, createHash } from 'node:crypto';
import canonicalize from 'canonicalize';
import { verifyLedger } from '../src/verify.ts';
import { coreOf, hashCore, readEntries, signCore, genesisPrev, type LedgerEntry } from '../src/ledger.ts';
import { keyIdOf } from '../src/keys.ts';
import { hashedRekordBody } from '../src/rekor.ts';
import { leafHash } from '../src/merkle.ts';
import { buildAnchoredLedger, fakeRekor } from './helpers.ts';

function readLines(ledgerDir: string): string[] {
  return readFileSync(join(ledgerDir, 'ledger.jsonl'), 'utf8').trimEnd().split('\n');
}

function writeLines(ledgerDir: string, lines: string[]): void {
  writeFileSync(join(ledgerDir, 'ledger.jsonl'), lines.join('\n') + '\n');
}

test('pristine anchored ledger verifies: exit 0', async () => {
  const { ledgerDir, rekor } = buildAnchoredLedger();
  const report = await verifyLedger(ledgerDir, { rekorPubPem: rekor.publicPem });
  assert.equal(report.exitCode, 0, JSON.stringify(report.findings, null, 2));
  assert.equal(report.result, 'VERIFIED');
  const anchor = report.checks.find((c) => c.name === 'ANCHOR')!;
  assert.ok(anchor.ok);
  assert.ok(!anchor.warn, 'authenticated against the trusted Rekor key');
  assert.ok(anchor.lines[0]!.includes('authenticated'));
});

test('without a trusted Rekor key, anchors are reported UNAUTHENTICATED, not verified', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  // no --rekor-key and no host pin: the key shipped inside the artifact must
  // NOT be used to authenticate the artifact.
  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 0);
  const anchor = report.checks.find((c) => c.name === 'ANCHOR')!;
  assert.ok(anchor.ok);
  assert.ok(anchor.warn, 'must warn that anchors are unauthenticated');
  assert.ok(anchor.lines.some((l) => l.includes('NOT authenticated')));
});

test('core-field mutation: exit 1, blast radius from tampered entry', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  const e = JSON.parse(lines[7]!) as LedgerEntry;
  e.ts = '1999-01-01T00:00:00.000Z'; // rewrite history
  lines[7] = JSON.stringify(e);
  writeLines(ledgerDir, lines);

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1);
  assert.equal(report.result, 'TAMPER DETECTED');
  assert.equal(report.blastRadius?.from, 7);
  assert.equal(report.blastRadius?.to, lines.length - 1);
  assert.ok(report.findings.some((f) => f.check === 'CHAIN' && f.seq === 7));
  assert.ok(report.auditPacket);
});

test('payload mutation (the demo attack): payload_hash catches it', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  const idx = lines.findIndex((l) => l.includes('100.00'));
  lines[idx] = lines[idx]!.replace('100.00', '100000.00');
  writeLines(ledgerDir, lines);

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1);
  assert.ok(
    report.findings.some((f) => f.check === 'CHAIN' && f.reason.includes('payload')),
  );
});

test('deleted middle line: seq gap detected', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  lines.splice(5, 1);
  writeLines(ledgerDir, lines);

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1);
  assert.ok(report.findings.some((f) => f.check === 'CHAIN' && f.reason.includes('seq')));
});

test('swapped lines: chain break detected', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  [lines[3], lines[4]] = [lines[4]!, lines[3]!];
  writeLines(ledgerDir, lines);

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1);
});

test('post-anchor truncation: orphaned stored anchor detected offline', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  // attacker truncates the tail including checkpoint + anchor entries
  writeLines(ledgerDir, lines.slice(0, 6));

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1);
  assert.ok(
    report.findings.some((f) => f.check === 'ANCHOR' && f.reason.includes('truncation')),
    JSON.stringify(report.findings),
  );
});

test('truncation into anchored region with checkpoint retained: MERKLE fails', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  const kept = [...lines.slice(0, 4), ...lines.slice(-2)]; // keep ckpt+anchor, drop middle... broken chain too
  writeLines(ledgerDir, kept);
  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1);
});

test('re-sign entry with a foreign key: SIG catches key_id + signature', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  const attacker = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const e = JSON.parse(lines[2]!) as LedgerEntry;
  e.payload = JSON.stringify({ status: 'ok', duration_ms: 1 }); // attacker edit
  // attacker recomputes commitment, hash and re-signs with their own key
  const attackerKeyObj = attacker.publicKey;
  e.key_id = keyIdOf(attackerKeyObj);
  const core = coreOf(e as unknown as Record<string, unknown>);
  e.hash = hashCore(core);
  e.sig = signCore(core, attacker.privateKey);
  lines[2] = JSON.stringify(e);
  writeLines(ledgerDir, lines);

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1);
  // chain break at 3 (prev mismatch) is expected; the key mismatch at 2 must also be flagged
  assert.ok(report.findings.some((f) => f.check === 'SIG' && f.seq === 2));
});

test('full rewrite + re-sign with attacker key, anchors kept: ANCHOR catches offline', async () => {
  const { ledgerDir, ledgerId } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  const entries = lines.map((l) => JSON.parse(l) as LedgerEntry);
  // attacker generates their own recorder key and rewrites EVERYTHING,
  // including genesis (their pubkey) — self-consistent chain + sigs
  const atk = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const atkPem = atk.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const atkKeyId = keyIdOf(atk.publicKey);
  let prev = genesisPrev(ledgerId);
  const rewritten: string[] = [];
  const newHashes: string[] = [];
  for (const e of entries) {
    if (e.type === 'genesis') {
      e.payload = JSON.stringify({ ledger_id: ledgerId, public_key_pem: atkPem, attestor_version: 1 });
    }
    if (e.payload?.includes('100.00')) {
      e.payload = e.payload.replace('100.00', '100000.00');
    }
    if (e.type === 'checkpoint') {
      // attacker recomputes the checkpoint root over rewritten entries
      const payload = JSON.parse(e.payload!) as { ledger_id: string; tree_size: number; root: string };
      const { merkleRoot } = await import('../src/merkle.ts');
      payload.root = merkleRoot(newHashes.slice(0, payload.tree_size).map((h) => Buffer.from(h, 'hex'))).toString('hex');
      e.payload = JSON.stringify(payload);
    }
    e.key_id = atkKeyId;
    e.prev = prev;
    const { createHash: ch } = await import('node:crypto');
    e.salt = ch('sha256').update(e.hash).digest('hex').slice(0, 32); // deterministic new salt
    e.payload_hash = (await import('../src/ledger.ts')).payloadHash(e.salt, e.payload);
    const core = coreOf(e as unknown as Record<string, unknown>);
    e.hash = hashCore(core);
    e.sig = signCore(core, atk.privateKey);
    prev = e.hash;
    newHashes.push(e.hash);
    rewritten.push(JSON.stringify(e));
  }
  writeLines(ledgerDir, rewritten);

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1);
  // CHAIN, MERKLE, SIG all pass — only the anchor gives the attacker away
  assert.ok(report.checks.find((c) => c.name === 'CHAIN')?.ok, 'attacker chain is self-consistent');
  assert.ok(report.checks.find((c) => c.name === 'SIG')?.ok, 'attacker sigs are self-consistent');
  assert.ok(
    report.findings.some((f) => f.check === 'ANCHOR' && f.reason.includes('anchored')),
    JSON.stringify(report.findings),
  );
});

test('forged anchor file (attacker fake Rekor key): SET verification fails', async () => {
  const { ledgerDir, rekor } = buildAnchoredLedger();
  // attacker re-signs the stored anchor with their own "Rekor" key AND ships
  // the matching key inside the artifact — the auditor's trusted key wins.
  const lines = readLines(ledgerDir);
  const anchor = lines.map((l) => JSON.parse(l) as LedgerEntry).find((e) => e.type === 'anchor')!;
  const ckptSeq = (JSON.parse(anchor.payload!) as { checkpoint_seq: number }).checkpoint_seq;
  const stored = JSON.parse(readFileSync(join(ledgerDir, 'anchors', `${ckptSeq}.json`), 'utf8'));
  const fake = fakeRekor();
  const setCanon = canonicalize({
    body: stored.body,
    integratedTime: stored.integratedTime,
    logID: stored.logID,
    logIndex: stored.logIndex,
  })!;
  stored.verification.signedEntryTimestamp = cryptoSign(
    'sha256',
    Buffer.from(setCanon, 'utf8'),
    fake.privateKey,
  ).toString('base64');
  writeFileSync(join(ledgerDir, 'anchors', `${ckptSeq}.json`), JSON.stringify(stored));
  // the attacker also swaps the artifact's own copy of the log key to match
  writeFileSync(join(ledgerDir, 'anchors', 'rekor-pub.pem'), fake.publicPem);

  const report = await verifyLedger(ledgerDir, { rekorPubPem: rekor.publicPem });
  assert.equal(report.exitCode, 1);
  assert.ok(report.findings.some((f) => f.check === 'ANCHOR' && f.reason.includes('SET')));
});

test('redacted entry still verifies: exit 0', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  const idx = lines.findIndex((l) => l.includes('100.00'));
  const e = JSON.parse(lines[idx]!) as LedgerEntry;
  delete e.payload; // redaction drops the unsigned payload, nothing else
  lines[idx] = JSON.stringify(e);
  writeLines(ledgerDir, lines);

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 0, JSON.stringify(report.findings));
  assert.ok(report.checks.find((c) => c.name === 'CHAIN')?.lines[0]?.includes('redacted'));
});

test('anchor lag reported for entries after last anchored checkpoint', async () => {
  const { ledgerDir, keys } = buildAnchoredLedger();
  const { Ledger } = await import('../src/ledger.ts');
  const ledger = Ledger.open(ledgerDir, keys);
  ledger.append({ type: 'wire', origin: 'proxy', payload: '"post-anchor traffic"' });
  ledger.close();

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 0);
  assert.ok(report.anchorLag);
  assert.ok(report.anchorLag!.count >= 1);
});

test('redaction drops the salt too, so payload_hash cannot be brute-forced', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const entries = readEntries(join(ledgerDir, 'ledger.jsonl'));
  const target = entries.find((e) => e.payload?.includes('100.00'))!;
  const { redactEntry } = await import('../src/redact.ts');
  const redacted = redactEntry(ledgerDir, target.seq);
  assert.equal(redacted.payload, undefined);
  assert.equal(redacted.salt, undefined, 'salt must not survive redaction');
  assert.equal(redacted.payload_hash, target.payload_hash, 'commitment survives');
  // a guesser who knows the exact plaintext still cannot confirm it
  const { payloadHash } = await import('../src/ledger.ts');
  assert.notEqual(payloadHash(undefined, target.payload), target.payload_hash);
  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 0, JSON.stringify(report.findings));
});

test('stripping a system payload (gap / checkpoint) is tamper, not redaction', async () => {
  for (const type of ['gap', 'checkpoint'] as const) {
    const { ledgerDir, keys } = buildAnchoredLedger();
    if (type === 'gap') {
      const { Ledger } = await import('../src/ledger.ts');
      const l = Ledger.open(ledgerDir, keys);
      l.append({ type: 'gap', origin: 'proxy', payload: JSON.stringify({ unrecorded_lines: 9 }) });
      l.close();
    }
    const lines = readLines(ledgerDir);
    const idx = lines.findIndex((l) => (JSON.parse(l) as LedgerEntry).type === type);
    const e = JSON.parse(lines[idx]!) as LedgerEntry;
    delete e.payload;
    delete e.salt;
    lines[idx] = JSON.stringify(e);
    writeLines(ledgerDir, lines);

    const report = await verifyLedger(ledgerDir);
    assert.equal(report.exitCode, 1, `${type} payload strip must be tamper`);
    assert.ok(report.findings.some((f) => f.reason.includes('not redactable')), `${type}: ${JSON.stringify(report.findings)}`);
  }
});

test('unknown unsigned top-level field is rejected', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  const e = JSON.parse(lines[4]!) as LedgerEntry & { note?: string };
  e.note = 'attacker-supplied annotation the signature does not cover';
  lines[4] = JSON.stringify(e);
  writeLines(ledgerDir, lines);

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1);
  assert.ok(report.findings.some((f) => f.reason.includes('unknown unsigned field')));
});

test('anchor signed by a rotated recorder key is accepted (rotate then drain queue)', async () => {
  const { ledgerDir, keys, rekor } = buildAnchoredLedger();
  const { Ledger } = await import('../src/ledger.ts');
  const { generateKey } = await import('../src/keys.ts');
  const { writeCheckpoint } = await import('../src/checkpoint.ts');
  const { fakeAnchor } = await import('./helpers.ts');
  const ledger = Ledger.open(ledgerDir, keys);
  const newKeys = generateKey(join(ledgerDir, '..', 'home2'));
  ledger.append({ type: 'key_rotation', origin: 'system', payload: newKeys.publicPem });
  ledger.close();
  // subsequent entries + anchor are produced with the NEW key
  const ledger2 = Ledger.open(ledgerDir, newKeys);
  ledger2.append({ type: 'wire', origin: 'proxy', payload: '"post-rotation"' });
  const ckpt = writeCheckpoint(ledger2);
  fakeAnchor(ledger2, ckpt, rekor);
  ledger2.close();

  const report = await verifyLedger(ledgerDir, { rekorPubPem: rekor.publicPem });
  assert.equal(report.exitCode, 0, JSON.stringify(report.findings, null, 2));
});

test('--entry SEQ: inclusion path to nearest covering (anchored) checkpoint', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const report = await verifyLedger(ledgerDir, { entry: 3 });
  assert.equal(report.exitCode, 0);
  assert.ok(report.entryFocus);
  assert.equal(report.entryFocus!.seq, 3);
  assert.equal(report.entryFocus!.ok, true);
  assert.equal(report.entryFocus!.anchored, true);
  assert.ok(report.entryFocus!.proofLength! >= 1);
});

test('--entry SEQ on a tampered entry reports inclusion failure', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  const e = JSON.parse(lines[3]!) as LedgerEntry;
  e.ts = '1999-01-01T00:00:00.000Z';
  lines[3] = JSON.stringify(e);
  writeLines(ledgerDir, lines);
  const report = await verifyLedger(ledgerDir, { entry: 3 });
  assert.equal(report.exitCode, 1);
  assert.equal(report.entryFocus!.ok, false);
});

test('--entry SEQ out of range is reported, not crashed', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const report = await verifyLedger(ledgerDir, { entry: 9999 });
  assert.ok(report.entryFocus);
  assert.equal(report.entryFocus!.ok, false);
  assert.ok(report.entryFocus!.note.includes('out of range'));
});

test('missing anchor file for anchor entry: fails', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  const anchor = lines.map((l) => JSON.parse(l) as LedgerEntry).find((e) => e.type === 'anchor')!;
  const ckptSeq = (JSON.parse(anchor.payload!) as { checkpoint_seq: number }).checkpoint_seq;
  unlinkSync(join(ledgerDir, 'anchors', `${ckptSeq}.json`));

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1);
});
