// Checkpoint cadence: 64 new entries ∨ 60 s idle ∨ session end, whichever
// first. A checkpoint entry commits {ledger_id, tree_size, root} — the RFC
// 6962 root over all entry hashes [0, tree_size). The payload is bound by the
// signed core's payload_hash, and checkpoint entries are never redactable.
import type { Ledger, LedgerEntry } from './ledger.ts';
import { merkleRoot } from './merkle.ts';

export interface CheckpointPayload {
  ledger_id: string;
  tree_size: number;
  root: string;
}

export function computeRootHex(entryHashes: readonly string[], treeSize: number): string {
  const leaves = entryHashes.slice(0, treeSize).map((h) => Buffer.from(h, 'hex'));
  return merkleRoot(leaves).toString('hex');
}

/** Append a checkpoint entry covering every entry currently in the ledger. */
export function writeCheckpoint(ledger: Ledger, sessionId?: string): LedgerEntry {
  const tree_size = ledger.size;
  const payload: CheckpointPayload = {
    ledger_id: ledger.ledgerId,
    tree_size,
    root: computeRootHex(ledger.hashes, tree_size),
  };
  return ledger.append({
    type: 'checkpoint',
    origin: 'system',
    payload: JSON.stringify(payload),
    session_id: sessionId,
  });
}

/** Highest tree_size already covered by a checkpoint in `entries`. */
export function lastCheckpointSize(entries: readonly LedgerEntry[]): number {
  for (let i = entries.length - 1; i >= 0; i--) {
    const e = entries[i]!;
    if (e.type === 'checkpoint' && e.payload !== undefined) {
      try {
        return (JSON.parse(e.payload) as CheckpointPayload).tree_size;
      } catch {
        return 0;
      }
    }
  }
  return 0;
}

export interface CheckpointerOptions {
  maxEntries?: number;
  idleMs?: number;
  /** Called with each new checkpoint entry (anchoring hook). */
  onCheckpoint?: (entry: LedgerEntry) => void;
  /** Entries already covered by the latest existing checkpoint. */
  initialCoveredSize?: number;
}

export class Checkpointer {
  private readonly ledger: Ledger;
  private readonly maxEntries: number;
  private readonly idleMs: number;
  private readonly onCheckpoint: ((entry: LedgerEntry) => void) | undefined;
  private covered: number;
  private idleTimer: NodeJS.Timeout | undefined;
  private sessionId: string | undefined;

  constructor(ledger: Ledger, opts: CheckpointerOptions = {}) {
    this.ledger = ledger;
    this.maxEntries = opts.maxEntries ?? 64;
    this.idleMs = opts.idleMs ?? 60_000;
    this.onCheckpoint = opts.onCheckpoint;
    this.covered = opts.initialCoveredSize ?? ledger.size;
  }

  setSession(sessionId: string): void {
    this.sessionId = sessionId;
  }

  /** Call after every non-checkpoint append. */
  noteActivity(): void {
    if (this.ledger.size - this.covered >= this.maxEntries) {
      this.checkpointNow();
      return;
    }
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = setTimeout(() => this.checkpointNow(), this.idleMs);
    this.idleTimer.unref();
  }

  /** Checkpoint immediately if there is anything new to cover. */
  checkpointNow(): LedgerEntry | undefined {
    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
      this.idleTimer = undefined;
    }
    if (this.ledger.size <= this.covered) return undefined;
    const entry = writeCheckpoint(this.ledger, this.sessionId);
    this.covered = this.ledger.size; // includes the checkpoint entry itself
    this.onCheckpoint?.(entry);
    return entry;
  }

  stop(): void {
    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
      this.idleTimer = undefined;
    }
  }
}
