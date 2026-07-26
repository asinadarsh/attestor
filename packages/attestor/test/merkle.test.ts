import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  consistencyProof,
  inclusionProof,
  leafHash,
  merkleRoot,
  verifyConsistency,
  verifyInclusion,
} from '../src/merkle.ts';
import { Checkpointer, computeRootHex, lastCheckpointSize, writeCheckpoint } from '../src/checkpoint.ts';
import { generateKey } from '../src/keys.ts';
import { Ledger, readEntries } from '../src/ledger.ts';

const vectorsPath = join(dirname(fileURLToPath(import.meta.url)), 'vectors', 'rfc6962.json');
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8')) as {
  emptyRoot: string;
  leavesHex: string[];
  roots: string[];
};
const LEAVES = vectors.leavesHex.map((h) => Buffer.from(h, 'hex'));

test('RFC 6962 known-answer roots, sizes 0-8', () => {
  assert.equal(merkleRoot([]).toString('hex'), vectors.emptyRoot);
  for (let n = 1; n <= LEAVES.length; n++) {
    assert.equal(
      merkleRoot(LEAVES.slice(0, n)).toString('hex'),
      vectors.roots[n - 1],
      `root at size ${n}`,
    );
  }
});

test('inclusion proof verifies for every leaf at every size (incl. unbalanced)', () => {
  for (let n = 1; n <= LEAVES.length; n++) {
    const subset = LEAVES.slice(0, n);
    const root = merkleRoot(subset);
    for (let m = 0; m < n; m++) {
      const proof = inclusionProof(m, subset);
      assert.ok(
        verifyInclusion(m, n, leafHash(subset[m]!), proof, root),
        `inclusion leaf ${m} of ${n}`,
      );
      // wrong leaf index must fail
      if (n > 1) {
        assert.ok(!verifyInclusion((m + 1) % n, n, leafHash(subset[m]!), proof, root));
      }
      // corrupted proof node must fail
      if (proof.length > 0) {
        const bad = proof.map((b) => Buffer.from(b));
        bad[0] = Buffer.alloc(32, 7);
        assert.ok(!verifyInclusion(m, n, leafHash(subset[m]!), bad, root));
      }
    }
  }
});

test('consistency proof verifies for every m<=n pair; corrupted fails', () => {
  for (let n = 1; n <= LEAVES.length; n++) {
    const bigRoot = merkleRoot(LEAVES.slice(0, n));
    for (let m = 1; m <= n; m++) {
      const oldRoot = merkleRoot(LEAVES.slice(0, m));
      const proof = consistencyProof(m, LEAVES.slice(0, n));
      assert.ok(
        verifyConsistency(m, n, oldRoot, bigRoot, proof),
        `consistency ${m} -> ${n}`,
      );
      if (proof.length > 0) {
        const bad = proof.map((b) => Buffer.from(b));
        bad[bad.length - 1] = Buffer.alloc(32, 9);
        assert.ok(!verifyConsistency(m, n, oldRoot, bigRoot, bad));
      }
      // wrong old root must fail when growth happened
      if (m < n) {
        assert.ok(!verifyConsistency(m, n, Buffer.alloc(32, 1), bigRoot, proof));
      }
    }
  }
});

test('checkpoint entry commits reproducible root; cadence by entry count', () => {
  const dir = mkdtempSync(join(tmpdir(), 'attestor-ckpt-'));
  const keys = generateKey(join(dir, 'home'));
  const ledger = Ledger.open(join(dir, 'ledger'), keys);
  const checkpoints: number[] = [];
  const ckpt = new Checkpointer(ledger, {
    maxEntries: 5,
    idleMs: 3600_000,
    onCheckpoint: (e) => checkpoints.push(e.seq),
  });
  for (let i = 0; i < 12; i++) {
    ledger.append({ type: 'wire', origin: 'proxy', payload: String(i) });
    ckpt.noteActivity();
  }
  const final = ckpt.checkpointNow(); // session end
  assert.ok(final);
  ckpt.stop();
  ledger.close();

  const entries = readEntries(join(dir, 'ledger', 'ledger.jsonl'));
  const ckptEntries = entries.filter((e) => e.type === 'checkpoint');
  assert.ok(ckptEntries.length >= 2, 'cadence produced multiple checkpoints');
  for (const c of ckptEntries) {
    const payload = JSON.parse(c.payload!) as { tree_size: number; root: string };
    assert.equal(payload.tree_size, c.seq, 'checkpoint covers everything before it');
    const hashes = entries.slice(0, payload.tree_size).map((e) => e.hash);
    assert.equal(computeRootHex(hashes, payload.tree_size), payload.root);
  }
  // successive checkpoint roots are consistent (append-only growth)
  const [a, b] = ckptEntries.slice(-2).map((c) => JSON.parse(c.payload!) as { tree_size: number; root: string });
  const allLeaves = entries.map((e) => Buffer.from(e.hash, 'hex'));
  const proof = consistencyProof(a!.tree_size, allLeaves.slice(0, b!.tree_size));
  assert.ok(
    verifyConsistency(
      a!.tree_size,
      b!.tree_size,
      Buffer.from(a!.root, 'hex'),
      Buffer.from(b!.root, 'hex'),
      proof,
    ),
  );
  assert.equal(lastCheckpointSize(entries), b!.tree_size);
});

test('idle timer triggers checkpoint', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'attestor-idle-'));
  const keys = generateKey(join(dir, 'home'));
  const ledger = Ledger.open(join(dir, 'ledger'), keys);
  let fired = 0;
  const ckpt = new Checkpointer(ledger, {
    maxEntries: 1000,
    idleMs: 50,
    onCheckpoint: () => fired++,
  });
  ledger.append({ type: 'wire', origin: 'proxy', payload: '"x"' });
  ckpt.noteActivity();
  await new Promise((r) => setTimeout(r, 150));
  assert.equal(fired, 1);
  ckpt.stop();
  ledger.close();
});

test('writeCheckpoint on empty-but-genesis ledger covers genesis', () => {
  const dir = mkdtempSync(join(tmpdir(), 'attestor-g-'));
  const keys = generateKey(join(dir, 'home'));
  const ledger = Ledger.open(join(dir, 'ledger'), keys);
  const c = writeCheckpoint(ledger);
  const payload = JSON.parse(c.payload!) as { tree_size: number };
  assert.equal(payload.tree_size, 1);
  ledger.close();
});
