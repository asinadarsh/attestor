// Verify CLI core: CHAIN → MERKLE → SIG → ANCHOR (offline) → ANCHOR-ONLINE.
// Exit codes: 0 verified · 1 tamper · 2 usage/IO error · 3 --online requested
// but Rekor unreachable. Never trusts stored `hash` fields — every check runs
// over recomputed hashes from the signed cores.
import { createPublicKey, type KeyObject } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { attestorHome, keyIdOf, keysDir } from './keys.ts';
import {
  coreOf,
  genesisPrev,
  hashCore,
  payloadHash,
  verifyCoreSig,
  type LedgerEntry,
} from './ledger.ts';
import { computeRootHex, type CheckpointPayload } from './checkpoint.ts';
import {
  getEntry,
  RekorUnavailableError,
  verifyCheckpointNote,
  verifyRekorInclusion,
  verifySET,
  type AnchorPayload,
  type RekorEntry,
} from './rekor.ts';

export interface TamperFinding {
  seq: number;
  check: 'CHAIN' | 'MERKLE' | 'SIG' | 'ANCHOR' | 'ANCHOR-ONLINE';
  reason: string;
  expected?: string;
  got?: string;
}

export interface CheckLine {
  name: string;
  ok: boolean;
  skipped?: boolean;
  lines: string[];
}

export interface VerifyReport {
  result: 'VERIFIED' | 'TAMPER DETECTED' | 'ERROR' | 'REKOR UNREACHABLE';
  exitCode: 0 | 1 | 2 | 3;
  checks: CheckLine[];
  findings: TamperFinding[];
  blastRadius?: { from: number; to: number };
  anchorLag?: { count: number; fromSeq: number; toSeq: number };
  entryCount: number;
  ledgerId?: string;
  auditPacket?: Record<string, unknown>;
}

export interface VerifyOptions {
  online?: boolean;
  entry?: number;
  rekorUrl?: string;
}

interface ResolvedLedger {
  entries: LedgerEntry[];
  anchorFile: (checkpointSeq: number) => string | undefined;
  storedAnchorSeqs: number[];
  rekorPubPem: string | undefined;
}

/** Accepts a live ledger dir, an exported evidence pack, or a ledger.jsonl path. */
function resolveTarget(target: string): ResolvedLedger {
  let ledgerPath: string | undefined;
  let base = target;
  if (target.endsWith('.jsonl')) {
    ledgerPath = target;
    base = join(target, '..');
  } else {
    for (const candidate of ['ledger.jsonl', join('ledger', 'entries.jsonl')]) {
      if (existsSync(join(target, candidate))) {
        ledgerPath = join(target, candidate);
        break;
      }
    }
  }
  if (!ledgerPath || !existsSync(ledgerPath)) {
    throw new Error(`no ledger found at ${target} (expected ledger.jsonl or ledger/entries.jsonl)`);
  }
  const entries: LedgerEntry[] = [];
  const raw = readFileSync(ledgerPath, 'utf8');
  let lineNo = 0;
  for (const line of raw.split('\n')) {
    lineNo++;
    if (line === '') continue;
    try {
      entries.push(JSON.parse(line) as LedgerEntry);
    } catch {
      throw new Error(`unparsable ledger line ${lineNo}`);
    }
  }
  const anchorDirs = [join(base, 'anchors'), join(base, 'anchors', 'rekor')];
  const anchorFile = (seq: number): string | undefined => {
    for (const d of anchorDirs) {
      const p = join(d, `${seq}.json`);
      if (existsSync(p)) return p;
    }
    return undefined;
  };
  const storedAnchorSeqs: number[] = [];
  for (const d of anchorDirs) {
    if (!existsSync(d)) continue;
    for (const f of readdirSync(d)) {
      const m = /^(\d+)\.json$/.exec(f);
      if (m) storedAnchorSeqs.push(Number(m[1]));
    }
  }
  let rekorPubPem: string | undefined;
  for (const p of [
    join(base, 'anchors', 'rekor-pub.pem'),
    join(base, 'keys', 'rekor-pub.pem'),
    join(keysDir(attestorHome()), 'rekor-pub.pem'),
  ]) {
    if (existsSync(p)) {
      rekorPubPem = readFileSync(p, 'utf8');
      break;
    }
  }
  return { entries, anchorFile, storedAnchorSeqs: [...new Set(storedAnchorSeqs)].sort((a, b) => a - b), rekorPubPem };
}

export async function verifyLedger(target: string, opts: VerifyOptions = {}): Promise<VerifyReport> {
  let resolved: ResolvedLedger;
  try {
    resolved = resolveTarget(target);
  } catch (err) {
    return {
      result: 'ERROR',
      exitCode: 2,
      checks: [],
      findings: [],
      entryCount: 0,
      auditPacket: { error: (err as Error).message },
    };
  }
  const { entries, anchorFile, storedAnchorSeqs, rekorPubPem } = resolved;
  const findings: TamperFinding[] = [];
  const checks: CheckLine[] = [];
  const n = entries.length;

  if (n === 0) {
    return {
      result: 'ERROR',
      exitCode: 2,
      checks: [],
      findings: [],
      entryCount: 0,
      auditPacket: { error: 'empty ledger' },
    };
  }

  // ---- CHAIN ----------------------------------------------------------
  const genesis = entries[0]!;
  let ledgerId: string | undefined;
  let genesisPubPem: string | undefined;
  if (genesis.type !== 'genesis' || genesis.payload === undefined) {
    findings.push({ seq: 0, check: 'CHAIN', reason: 'first entry is not a genesis entry with payload' });
  } else {
    try {
      const gp = JSON.parse(genesis.payload) as { ledger_id: string; public_key_pem: string };
      ledgerId = gp.ledger_id;
      genesisPubPem = gp.public_key_pem;
    } catch {
      findings.push({ seq: 0, check: 'CHAIN', reason: 'genesis payload unparsable' });
    }
  }

  const recomputed: string[] = [];
  let redactedCount = 0;
  let prev = ledgerId !== undefined ? genesisPrev(ledgerId) : undefined;
  for (let i = 0; i < n; i++) {
    const e = entries[i]!;
    const core = coreOf(e as unknown as Record<string, unknown>);
    const h = hashCore(core);
    recomputed.push(h);
    if (e.seq !== i) {
      findings.push({
        seq: i,
        check: 'CHAIN',
        reason: `seq gap or reorder: expected seq ${i}, found ${e.seq} (deleted or swapped lines)`,
        expected: String(i),
        got: String(e.seq),
      });
      continue;
    }
    if (prev !== undefined && e.prev !== prev) {
      findings.push({
        seq: i,
        check: 'CHAIN',
        reason: `prev-hash link broken at entry ${i}`,
        expected: prev,
        got: e.prev,
      });
    }
    if (e.hash !== h) {
      findings.push({
        seq: i,
        check: 'CHAIN',
        reason: `entry ${i} core does not match its recorded hash (core field mutated)`,
        expected: h,
        got: e.hash,
      });
    }
    if (e.payload !== undefined) {
      if (payloadHash(e.salt, e.payload) !== e.payload_hash) {
        findings.push({
          seq: i,
          check: 'CHAIN',
          reason: `entry ${i} payload does not match its signed commitment (payload mutated)`,
          expected: e.payload_hash,
          got: payloadHash(e.salt, e.payload),
        });
      }
    } else if (!['session_end', 'session_start', 'gap'].includes(e.type)) {
      redactedCount++;
    }
    prev = h;
  }
  const chainOk = findings.filter((f) => f.check === 'CHAIN').length === 0;
  checks.push({
    name: 'CHAIN',
    ok: chainOk,
    lines: chainOk
      ? [
          `${n.toLocaleString('en-US')} entries, hash chain intact` +
            (redactedCount > 0 ? ` (${redactedCount} redacted payload${redactedCount === 1 ? '' : 's'})` : ''),
        ]
      : findingLines(findings, 'CHAIN'),
  });

  // ---- MERKLE ---------------------------------------------------------
  const checkpoints = entries.filter((e) => e.type === 'checkpoint');
  let merkleFailures = 0;
  const checkpointPayloads = new Map<number, CheckpointPayload>();
  for (const c of checkpoints) {
    if (c.payload === undefined) {
      findings.push({ seq: c.seq, check: 'MERKLE', reason: `checkpoint ${c.seq} payload missing (checkpoints are never redactable)` });
      merkleFailures++;
      continue;
    }
    let payload: CheckpointPayload;
    try {
      payload = JSON.parse(c.payload) as CheckpointPayload;
    } catch {
      findings.push({ seq: c.seq, check: 'MERKLE', reason: `checkpoint ${c.seq} payload unparsable` });
      merkleFailures++;
      continue;
    }
    checkpointPayloads.set(c.seq, payload);
    if (payload.tree_size > n) {
      findings.push({
        seq: c.seq,
        check: 'MERKLE',
        reason: `checkpoint ${c.seq} covers ${payload.tree_size} entries but ledger has only ${n} (post-anchor truncation)`,
        expected: `>= ${payload.tree_size} entries`,
        got: `${n} entries`,
      });
      merkleFailures++;
      continue;
    }
    const root = computeRootHex(recomputed, payload.tree_size);
    if (root !== payload.root) {
      findings.push({
        seq: c.seq,
        check: 'MERKLE',
        reason: `checkpoint ${c.seq} root mismatch over entries [0, ${payload.tree_size})`,
        expected: payload.root,
        got: root,
      });
      merkleFailures++;
    }
  }
  checks.push({
    name: 'MERKLE',
    ok: merkleFailures === 0,
    lines:
      merkleFailures === 0
        ? [`${checkpoints.length} checkpoint${checkpoints.length === 1 ? '' : 's'}, all roots reproduce`]
        : findingLines(findings, 'MERKLE'),
  });

  // ---- SIG (walks the key-rotation chain from genesis) ------------------
  let sigFailures = 0;
  let activePub: KeyObject | undefined;
  let activePem = genesisPubPem;
  const pemAtSeq: string[] = [];
  try {
    activePub = genesisPubPem !== undefined ? createPublicKey(genesisPubPem) : undefined;
  } catch {
    findings.push({ seq: 0, check: 'SIG', reason: 'genesis public key unparsable' });
    sigFailures++;
  }
  for (let i = 0; i < n && activePub !== undefined; i++) {
    const e = entries[i]!;
    pemAtSeq.push(activePem!);
    const core = coreOf(e as unknown as Record<string, unknown>);
    const expectedKeyId = keyIdOf(activePub);
    if (e.key_id !== expectedKeyId) {
      findings.push({
        seq: i,
        check: 'SIG',
        reason: `entry ${i} signed with unexpected key (re-signed with a foreign key?)`,
        expected: expectedKeyId,
        got: e.key_id,
      });
      sigFailures++;
    } else if (!verifyCoreSig(core, e.sig, activePub)) {
      findings.push({ seq: i, check: 'SIG', reason: `entry ${i} signature invalid` });
      sigFailures++;
    }
    if (e.type === 'key_rotation' && e.payload !== undefined) {
      try {
        activePub = createPublicKey(e.payload);
        activePem = e.payload;
      } catch {
        findings.push({ seq: i, check: 'SIG', reason: `key_rotation ${i} carries unparsable public key` });
        sigFailures++;
      }
    }
  }
  checks.push({
    name: 'SIG',
    ok: sigFailures === 0 && activePub !== undefined,
    lines:
      sigFailures === 0 && activePub !== undefined
        ? [`${n}/${n} entry signatures valid (key ${entries[n - 1]!.key_id})`]
        : findingLines(findings, 'SIG'),
  });

  // ---- ANCHOR (offline) -------------------------------------------------
  const anchorEntries = entries.filter((e) => e.type === 'anchor');
  const anchors: { payload: AnchorPayload; stored: RekorEntry & { uuid?: string } }[] = [];
  let anchorFailures = 0;
  let setChecked = 0;
  for (const a of anchorEntries) {
    if (a.payload === undefined) {
      findings.push({ seq: a.seq, check: 'ANCHOR', reason: `anchor ${a.seq} payload missing` });
      anchorFailures++;
      continue;
    }
    let payload: AnchorPayload;
    try {
      payload = JSON.parse(a.payload) as AnchorPayload;
    } catch {
      findings.push({ seq: a.seq, check: 'ANCHOR', reason: `anchor ${a.seq} payload unparsable` });
      anchorFailures++;
      continue;
    }
    const file = anchorFile(payload.checkpoint_seq);
    if (file === undefined) {
      findings.push({
        seq: a.seq,
        check: 'ANCHOR',
        reason: `anchor ${a.seq}: stored Rekor entry anchors/${payload.checkpoint_seq}.json missing`,
      });
      anchorFailures++;
      continue;
    }
    const stored = JSON.parse(readFileSync(file, 'utf8')) as RekorEntry & { uuid?: string };
    anchors.push({ payload, stored });
    const ckptEntry = entries[payload.checkpoint_seq];
    if (!ckptEntry || ckptEntry.type !== 'checkpoint') {
      findings.push({
        seq: a.seq,
        check: 'ANCHOR',
        reason: `anchor ${a.seq} references seq ${payload.checkpoint_seq}, which is not a checkpoint`,
      });
      anchorFailures++;
      continue;
    }
    // The anchored artifact is the checkpoint's JCS core bytes — recompute.
    const artifactHash = recomputed[payload.checkpoint_seq]!;
    let decoded: { kind?: string; spec?: { data?: { hash?: { value?: string } }; signature?: { publicKey?: { content?: string } } } };
    try {
      decoded = JSON.parse(Buffer.from(stored.body, 'base64').toString('utf8'));
    } catch {
      findings.push({ seq: a.seq, check: 'ANCHOR', reason: `anchor ${a.seq}: stored Rekor body undecodable` });
      anchorFailures++;
      continue;
    }
    const anchoredHash = decoded.spec?.data?.hash?.value;
    if (anchoredHash !== artifactHash) {
      findings.push({
        seq: a.seq,
        check: 'ANCHOR',
        reason: `checkpoint ${payload.checkpoint_seq} does not match what was anchored in Rekor (logIndex ${payload.logIndex})`,
        expected: anchoredHash,
        got: artifactHash,
      });
      anchorFailures++;
      continue;
    }
    const anchoredPubPem = decoded.spec?.signature?.publicKey?.content
      ? Buffer.from(decoded.spec.signature.publicKey.content, 'base64').toString('utf8')
      : undefined;
    const expectedPem = pemAtSeq[payload.checkpoint_seq];
    if (anchoredPubPem !== undefined && expectedPem !== undefined) {
      try {
        if (keyIdOf(createPublicKey(anchoredPubPem)) !== keyIdOf(createPublicKey(expectedPem))) {
          findings.push({
            seq: a.seq,
            check: 'ANCHOR',
            reason: `anchor ${a.seq} was signed by a key other than the ledger's recorder key`,
          });
          anchorFailures++;
          continue;
        }
      } catch {
        /* unparsable pem already reported elsewhere */
      }
    }
    if (rekorPubPem !== undefined) {
      setChecked++;
      if (!verifySET(stored, rekorPubPem)) {
        findings.push({
          seq: a.seq,
          check: 'ANCHOR',
          reason: `anchor ${a.seq}: Rekor SET signature invalid (stored anchor forged?)`,
        });
        anchorFailures++;
        continue;
      }
      const proof = stored.verification?.inclusionProof;
      if (proof && !verifyRekorInclusion(stored)) {
        findings.push({ seq: a.seq, check: 'ANCHOR', reason: `anchor ${a.seq}: stored inclusion proof invalid` });
        anchorFailures++;
        continue;
      }
      if (proof && !verifyCheckpointNote(proof, rekorPubPem)) {
        findings.push({ seq: a.seq, check: 'ANCHOR', reason: `anchor ${a.seq}: Rekor checkpoint note signature invalid` });
        anchorFailures++;
      }
    }
  }
  // Orphaned stored anchors: a Rekor entry exists on disk for a checkpoint
  // seq that is no longer in the ledger → tail was truncated past an anchor.
  for (const seq of storedAnchorSeqs) {
    const inLedger = entries[seq]?.type === 'checkpoint';
    if (!inLedger) {
      findings.push({
        seq: Math.min(seq, n - 1),
        check: 'ANCHOR',
        reason: `stored Rekor anchor exists for checkpoint seq ${seq}, but the ledger ${seq >= n ? `ends at seq ${n - 1}` : 'has no checkpoint there'} (post-anchor truncation)`,
      });
      anchorFailures++;
    }
  }
  const anchorOk = anchorFailures === 0;
  const anchorSummary =
    anchorEntries.length === 0
      ? ['no anchors recorded — ledger is chain-protected only, not externally anchored']
      : [
          `${anchorEntries.length - anchorFailures}/${anchorEntries.length} anchored in Rekor` +
            (anchors.length > 0 ? ` (latest logIndex ${anchors[anchors.length - 1]!.payload.logIndex})` : '') +
            (rekorPubPem === undefined ? ' — SET not verified (no pinned Rekor key)' : `, SET+inclusion verified for ${setChecked}`),
        ];
  checks.push({
    name: 'ANCHOR',
    ok: anchorOk,
    lines: anchorOk ? anchorSummary : findingLines(findings, 'ANCHOR'),
  });

  // anchor lag: entries not covered by any verified anchor's checkpoint
  const anchoredSizes = anchors
    .filter((a) => checkpointPayloads.has(a.payload.checkpoint_seq))
    .map((a) => checkpointPayloads.get(a.payload.checkpoint_seq)!.tree_size);
  const maxAnchored = anchoredSizes.length > 0 ? Math.max(...anchoredSizes) : 0;
  const anchorLag =
    n > maxAnchored && anchorEntries.length > 0
      ? { count: n - maxAnchored, fromSeq: maxAnchored, toSeq: n - 1 }
      : undefined;

  // ---- ANCHOR-ONLINE ----------------------------------------------------
  let rekorUnreachable = false;
  if (opts.online) {
    let onlineFailures = 0;
    let checked = 0;
    for (const { payload, stored } of anchors) {
      try {
        const fresh = await getEntry(opts.rekorUrl ?? payload.url, payload.uuid);
        checked++;
        if (fresh.body !== stored.body) {
          findings.push({
            seq: payload.checkpoint_seq,
            check: 'ANCHOR-ONLINE',
            reason: `Rekor logIndex ${payload.logIndex}: public log body differs from stored anchor`,
          });
          onlineFailures++;
          continue;
        }
        const freshBodyHash = (JSON.parse(Buffer.from(fresh.body, 'base64').toString('utf8')) as {
          spec?: { data?: { hash?: { value?: string } } };
        }).spec?.data?.hash?.value;
        if (freshBodyHash !== recomputed[payload.checkpoint_seq]) {
          findings.push({
            seq: payload.checkpoint_seq,
            check: 'ANCHOR-ONLINE',
            reason: `local checkpoint ${payload.checkpoint_seq} does not match the public log (full-rewrite detected)`,
            expected: freshBodyHash,
            got: recomputed[payload.checkpoint_seq],
          });
          onlineFailures++;
          continue;
        }
        if (!verifyRekorInclusion(fresh)) {
          findings.push({
            seq: payload.checkpoint_seq,
            check: 'ANCHOR-ONLINE',
            reason: `fresh inclusion proof invalid for logIndex ${payload.logIndex}`,
          });
          onlineFailures++;
        }
      } catch (err) {
        if (err instanceof RekorUnavailableError) {
          rekorUnreachable = true;
          break;
        }
        throw err;
      }
    }
    checks.push({
      name: 'ANCHOR-ONLINE',
      ok: !rekorUnreachable && onlineFailures === 0,
      skipped: rekorUnreachable,
      lines: rekorUnreachable
        ? ['Rekor unreachable — cannot compare against the public log']
        : onlineFailures === 0
          ? [`${checked}/${anchors.length} anchors match the public log (fresh proofs verified)`]
          : findingLines(findings, 'ANCHOR-ONLINE'),
    });
  }

  // ---- verdict ----------------------------------------------------------
  const tamper = findings.length > 0;
  const firstSeq = tamper ? Math.min(...findings.map((f) => f.seq)) : undefined;
  const report: VerifyReport = {
    result: tamper ? 'TAMPER DETECTED' : rekorUnreachable ? 'REKOR UNREACHABLE' : 'VERIFIED',
    exitCode: tamper ? 1 : rekorUnreachable ? 3 : 0,
    checks,
    findings,
    entryCount: n,
    ...(ledgerId !== undefined && { ledgerId }),
    ...(tamper && {
      blastRadius: { from: firstSeq!, to: n - 1 },
    }),
    ...(anchorLag !== undefined && { anchorLag }),
  };
  if (tamper) {
    report.auditPacket = {
      attestor_audit_packet: 1,
      generated_at: new Date().toISOString(),
      ledger_id: ledgerId,
      result: 'TAMPER DETECTED',
      findings: findings.map((f) => ({
        seq: f.seq,
        check: f.check,
        reason: f.reason,
        ...(f.expected !== undefined && { expected: f.expected }),
        ...(f.got !== undefined && { got: f.got }),
      })),
      blast_radius: { from_seq: firstSeq, to_seq: n - 1 },
      anchors: anchors.map((a) => ({
        checkpoint_seq: a.payload.checkpoint_seq,
        log_index: a.payload.logIndex,
        rekor_url: a.payload.url,
        search_url: `https://search.sigstore.dev/?logIndex=${a.payload.logIndex}`,
      })),
    };
  }
  return report;
}

function findingLines(findings: TamperFinding[], check: string): string[] {
  return findings
    .filter((f) => f.check === check)
    .slice(0, 5)
    .flatMap((f) => {
      const lines = [f.reason];
      if (f.expected !== undefined && f.got !== undefined) {
        lines.push(`expected ${truncate(f.expected)}, got ${truncate(f.got)}`);
      }
      return lines;
    });
}

function truncate(s: string): string {
  return s.length > 20 ? `${s.slice(0, 8)}…${s.slice(-8)}` : s;
}

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';

export function renderReport(report: VerifyReport, useColor = process.stdout.isTTY ?? false): string {
  const c = (code: string, s: string) => (useColor ? `${code}${s}${RESET}` : s);
  const out: string[] = [];
  for (const check of report.checks) {
    const mark = check.skipped ? c(DIM, '∅') : check.ok ? c(GREEN, '✔') : c(RED, '✖');
    const first = check.lines[0] ?? '';
    out.push(`${mark} ${check.name.padEnd(8)} ${check.ok || check.skipped ? first : c(RED, first)}`);
    for (const extra of check.lines.slice(1)) {
      out.push(`           ${c(DIM, extra)}`);
    }
  }
  if (report.blastRadius) {
    out.push(`           ${c(RED, `blast radius: entries ${report.blastRadius.from}–${report.blastRadius.to} untrustworthy`)}`);
  }
  if (report.anchorLag) {
    out.push(
      `${c(DIM, 'ℹ')} ANCHOR LAG  ${report.anchorLag.count} entr${report.anchorLag.count === 1 ? 'y' : 'ies'} (seq ${report.anchorLag.fromSeq}–${report.anchorLag.toSeq}) after last anchor — chain-protected, not yet anchored`,
    );
  }
  out.push(
    `RESULT: ${
      report.exitCode === 0
        ? c(GREEN + BOLD, report.result)
        : c(RED + BOLD, report.result)
    }  (exit ${report.exitCode})`,
  );
  return out.join('\n');
}
