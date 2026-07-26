// Rekor v1 anchoring over plain fetch: hashedrekord POST, offline pending
// queue with jittered backoff, SET + inclusion-proof verification.
// The anchored artifact is always a checkpoint entry's JCS core bytes.
import canonicalize from 'canonicalize';
import { createHash, createPublicKey, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import type { KeyPair } from './keys.ts';
import { attestorHome, keysDir } from './keys.ts';
import {
  canonicalCoreBytes,
  coreOf,
  readEntries,
  sha256Hex,
  type Ledger,
  type LedgerEntry,
} from './ledger.ts';
import { leafHash, rootFromInclusion } from './merkle.ts';

export const DEFAULT_REKOR_URL = 'https://rekor.sigstore.dev';

export function rekorUrl(): string {
  return process.env.ATTESTOR_REKOR_URL ?? DEFAULT_REKOR_URL;
}

export interface RekorInclusionProof {
  checkpoint?: string;
  hashes: string[];
  logIndex: number;
  rootHash: string;
  treeSize: number;
}

export interface RekorEntry {
  body: string;
  integratedTime: number;
  logID: string;
  logIndex: number;
  verification?: {
    signedEntryTimestamp?: string;
    inclusionProof?: RekorInclusionProof;
  };
}

export interface HashedRekordSpec {
  apiVersion: '0.0.1';
  kind: 'hashedrekord';
  spec: {
    data: { hash: { algorithm: 'sha256'; value: string } };
    signature: {
      content: string;
      publicKey: { content: string };
    };
  };
}

export function hashedRekordBody(artifact: Buffer, keys: KeyPair): HashedRekordSpec {
  const sigDer = cryptoSign('sha256', artifact, keys.privateKey);
  return {
    apiVersion: '0.0.1',
    kind: 'hashedrekord',
    spec: {
      data: { hash: { algorithm: 'sha256', value: sha256Hex(artifact) } },
      signature: {
        content: sigDer.toString('base64'),
        publicKey: { content: Buffer.from(keys.publicPem).toString('base64') },
      },
    },
  };
}

export class RekorUnavailableError extends Error {}

/** POST an entry; handles 201 (created) and 409 (duplicate → fetch existing). */
export async function postEntry(
  baseUrl: string,
  body: HashedRekordSpec,
): Promise<{ uuid: string; entry: RekorEntry }> {
  let res: Response;
  try {
    res = await fetch(`${baseUrl}/api/v1/log/entries`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  } catch (err) {
    throw new RekorUnavailableError(`rekor unreachable: ${(err as Error).message}`);
  }
  if (res.status === 201) {
    const json = (await res.json()) as Record<string, RekorEntry>;
    const uuid = Object.keys(json)[0]!;
    return { uuid, entry: json[uuid]! };
  }
  if (res.status === 409) {
    const location = res.headers.get('location');
    if (!location) throw new Error('rekor 409 without Location header');
    const uuid = location.split('/').pop()!;
    return { uuid, entry: await getEntry(baseUrl, uuid) };
  }
  const text = await res.text().catch(() => '');
  if (res.status === 429 || res.status >= 500) {
    throw new RekorUnavailableError(`rekor ${res.status}: ${text.slice(0, 200)}`);
  }
  throw new Error(`rekor POST failed ${res.status}: ${text.slice(0, 200)}`);
}

export async function getEntry(baseUrl: string, uuid: string): Promise<RekorEntry> {
  let res: Response;
  try {
    res = await fetch(`${baseUrl}/api/v1/log/entries/${uuid}`);
  } catch (err) {
    throw new RekorUnavailableError(`rekor unreachable: ${(err as Error).message}`);
  }
  if (!res.ok) {
    const cls = res.status === 429 || res.status >= 500 ? RekorUnavailableError : Error;
    throw new cls(`rekor GET ${uuid} failed: ${res.status}`);
  }
  const json = (await res.json()) as Record<string, RekorEntry>;
  const entry = json[uuid] ?? Object.values(json)[0];
  if (!entry) throw new Error(`rekor GET ${uuid}: empty response`);
  return entry;
}

export async function getLogPublicKey(baseUrl: string): Promise<string> {
  let res: Response;
  try {
    res = await fetch(`${baseUrl}/api/v1/log/publicKey`);
  } catch (err) {
    throw new RekorUnavailableError(`rekor unreachable: ${(err as Error).message}`);
  }
  if (!res.ok) throw new RekorUnavailableError(`rekor publicKey failed: ${res.status}`);
  return res.text();
}

/**
 * Verify the Signed Entry Timestamp: ECDSA-P256-SHA256 by the Rekor log key
 * over JCS({body, integratedTime, logID, logIndex}).
 */
export function verifySET(entry: RekorEntry, rekorPubPem: string): boolean {
  const set = entry.verification?.signedEntryTimestamp;
  if (!set) return false;
  const canon = canonicalize({
    body: entry.body,
    integratedTime: entry.integratedTime,
    logID: entry.logID,
    logIndex: entry.logIndex,
  });
  if (canon === undefined) return false;
  try {
    return cryptoVerify(
      'sha256',
      Buffer.from(canon, 'utf8'),
      createPublicKey(rekorPubPem),
      Buffer.from(set, 'base64'),
    );
  } catch {
    return false;
  }
}

/**
 * Verify the entry's inclusion proof: RFC 6962 leaf over the decoded body
 * bytes, audit path up to the proof's rootHash.
 */
export function verifyRekorInclusion(entry: RekorEntry): boolean {
  const proof = entry.verification?.inclusionProof;
  if (!proof) return false;
  const bodyBytes = Buffer.from(entry.body, 'base64');
  const root = rootFromInclusion(
    proof.logIndex,
    proof.treeSize,
    leafHash(bodyBytes),
    proof.hashes.map((h) => Buffer.from(h, 'hex')),
  );
  return root !== undefined && root.toString('hex') === proof.rootHash;
}

/**
 * Verify the signed note in inclusionProof.checkpoint against the Rekor log
 * key, and that it commits the same root as the proof.
 * Note format: "<origin>\n<size>\n<b64 root>\n[extra lines]\n\n— <origin> <b64(4-byte hint ‖ sig)>\n"
 */
export function verifyCheckpointNote(proof: RekorInclusionProof, rekorPubPem: string): boolean {
  const note = proof.checkpoint;
  if (!note) return false;
  const sep = note.indexOf('\n\n');
  if (sep === -1) return false;
  const body = note.slice(0, sep + 1); // signed bytes: body incl. trailing \n
  const sigLines = note.slice(sep + 2).trim().split('\n');
  const bodyLines = body.trimEnd().split('\n');
  if (bodyLines.length < 3) return false;
  const noteRoot = Buffer.from(bodyLines[2]!, 'base64').toString('hex');
  if (noteRoot !== proof.rootHash) return false;
  if (Number(bodyLines[1]) !== proof.treeSize) return false;
  for (const line of sigLines) {
    const m = /^— \S+ (\S+)$/.exec(line);
    if (!m) continue;
    const sigBytes = Buffer.from(m[1]!, 'base64');
    const sig = sigBytes.subarray(4); // strip 4-byte key hint
    try {
      if (
        cryptoVerify('sha256', Buffer.from(body, 'utf8'), createPublicKey(rekorPubPem), sig)
      ) {
        return true;
      }
    } catch {
      /* try next sig line */
    }
  }
  return false;
}

export interface AnchorPayload {
  checkpoint_seq: number;
  provider: 'rekor-v1';
  uuid: string;
  logIndex: number;
  integratedTime: number;
  url: string;
}

interface PendingAnchor {
  checkpoint_seq: number;
  attempts: number;
  next_at: number; // epoch ms
}

export function anchorsDir(ledgerDir: string): string {
  return join(ledgerDir, 'anchors');
}

/** Jittered exponential backoff: 1 min → 1 h cap. */
export function backoffMs(attempts: number): number {
  const base = Math.min(60_000 * 2 ** attempts, 3_600_000);
  return Math.round(base * (0.5 + Math.random()));
}

/** POST the checkpoint artifact and record the anchor entry. Throws on failure. */
async function tryAnchor(
  ledger: Ledger,
  checkpointEntry: LedgerEntry,
  baseUrl: string,
  home?: string,
): Promise<LedgerEntry> {
  const dir = anchorsDir(ledger.dir);
  mkdirSync(dir, { recursive: true });
  const artifact = canonicalCoreBytes(coreOf(checkpointEntry as unknown as Record<string, unknown>));
  const { uuid, entry } = await postEntry(baseUrl, hashedRekordBody(artifact, ledger.keys));
  writeFileSync(join(dir, `${checkpointEntry.seq}.json`), JSON.stringify({ uuid, ...entry }, null, 2));
  await pinRekorKey(baseUrl, ledger.dir, home).catch(() => {});
  const payload: AnchorPayload = {
    checkpoint_seq: checkpointEntry.seq,
    provider: 'rekor-v1',
    uuid,
    logIndex: entry.logIndex,
    integratedTime: entry.integratedTime,
    url: baseUrl,
  };
  return ledger.append({
    type: 'anchor',
    origin: 'system',
    payload: JSON.stringify(payload),
    session_id: checkpointEntry.session_id,
  });
}

/**
 * Anchor a checkpoint entry to Rekor. Never throws on network failure —
 * queues to anchors/pending.jsonl instead. Anchoring never blocks recording.
 */
export async function anchorCheckpoint(
  ledger: Ledger,
  checkpointEntry: LedgerEntry,
  opts: { baseUrl?: string; offline?: boolean; home?: string } = {},
): Promise<LedgerEntry | undefined> {
  const baseUrl = opts.baseUrl ?? rekorUrl();
  const offline = opts.offline ?? process.env.ATTESTOR_OFFLINE === '1';
  if (offline) {
    queuePending(ledger.dir, checkpointEntry.seq, 0);
    return undefined;
  }
  try {
    return await tryAnchor(ledger, checkpointEntry, baseUrl, opts.home);
  } catch (err) {
    if (err instanceof RekorUnavailableError) {
      queuePending(ledger.dir, checkpointEntry.seq, 0);
      return undefined;
    }
    throw err;
  }
}

/** Pin the Rekor log public key on first successful anchor. */
export async function pinRekorKey(baseUrl: string, ledgerDir: string, home?: string): Promise<void> {
  const local = join(anchorsDir(ledgerDir), 'rekor-pub.pem');
  if (existsSync(local)) return;
  const pem = await getLogPublicKey(baseUrl);
  mkdirSync(anchorsDir(ledgerDir), { recursive: true });
  writeFileSync(local, pem);
  const homeKeys = keysDir(home ?? attestorHome());
  mkdirSync(homeKeys, { recursive: true });
  const homePin = join(homeKeys, 'rekor-pub.pem');
  if (!existsSync(homePin)) writeFileSync(homePin, pem);
}

function pendingPath(ledgerDir: string): string {
  return join(anchorsDir(ledgerDir), 'pending.jsonl');
}

export function readPending(ledgerDir: string): PendingAnchor[] {
  const p = pendingPath(ledgerDir);
  if (!existsSync(p)) return [];
  const bySeq = new Map<number, PendingAnchor>();
  for (const line of readFileSync(p, 'utf8').split('\n')) {
    if (!line) continue;
    const rec = JSON.parse(line) as PendingAnchor;
    bySeq.set(rec.checkpoint_seq, rec);
  }
  return [...bySeq.values()];
}

function writePendingAll(ledgerDir: string, records: PendingAnchor[]): void {
  mkdirSync(anchorsDir(ledgerDir), { recursive: true });
  writeFileSync(
    pendingPath(ledgerDir),
    records.map((r) => JSON.stringify(r) + '\n').join(''),
  );
}

function queuePending(ledgerDir: string, checkpointSeq: number, attempts: number): void {
  const all = readPending(ledgerDir).filter((r) => r.checkpoint_seq !== checkpointSeq);
  all.push({
    checkpoint_seq: checkpointSeq,
    attempts: attempts + 1,
    next_at: Date.now() + backoffMs(attempts),
  });
  writePendingAll(ledgerDir, all);
}

/** Retry queued anchors whose backoff has elapsed. Returns count anchored. */
export async function retryPending(
  ledger: Ledger,
  opts: { baseUrl?: string; home?: string; now?: number } = {},
): Promise<number> {
  if (process.env.ATTESTOR_OFFLINE === '1') return 0;
  const now = opts.now ?? Date.now();
  const pending = readPending(ledger.dir);
  if (pending.length === 0) return 0;
  const baseUrl = opts.baseUrl ?? rekorUrl();
  const entries = readEntries(join(ledger.dir, 'ledger.jsonl'));
  let anchored = 0;
  const survivors: PendingAnchor[] = [];
  for (const rec of pending) {
    if (rec.next_at > now) {
      survivors.push(rec);
      continue;
    }
    const ckpt = entries.find((e) => e.seq === rec.checkpoint_seq && e.type === 'checkpoint');
    if (!ckpt) continue; // no such checkpoint — drop the queue record
    try {
      await tryAnchor(ledger, ckpt, baseUrl, opts.home);
      anchored++;
    } catch (err) {
      if (!(err instanceof RekorUnavailableError)) throw err;
      survivors.push({
        checkpoint_seq: rec.checkpoint_seq,
        attempts: rec.attempts + 1,
        next_at: now + backoffMs(rec.attempts + 1),
      });
    }
  }
  writePendingAll(ledger.dir, survivors);
  return anchored;
}
