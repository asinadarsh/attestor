// Redaction: delete the unsigned `payload` of one entry and rewrite that
// line. Chain, signatures, Merkle roots, and Rekor anchors all stay valid,
// because the signed core commits payload_hash = SHA256(salt ‖ payload) —
// never the payload itself. The random salt defeats brute-force on
// low-entropy redacted payloads. System entries (genesis, checkpoint,
// anchor, key_rotation) are never redactable: their payloads are
// load-bearing for verification.
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { SYSTEM_TYPES, type LedgerEntry } from './ledger.ts';

export function redactEntry(ledgerDir: string, seq: number): LedgerEntry {
  const path = join(ledgerDir, 'ledger.jsonl');
  if (!existsSync(path)) throw new Error(`no ledger at ${ledgerDir}`);
  const lockPath = join(ledgerDir, 'ledger.lock');
  if (existsSync(lockPath)) {
    const pid = Number(readFileSync(lockPath, 'utf8').trim());
    try {
      process.kill(pid, 0);
      throw new Error(`ledger is being written by pid ${pid} — stop the recorder first`);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ESRCH') throw err;
    }
  }
  const lines = readFileSync(path, 'utf8').trimEnd().split('\n');
  if (seq < 0 || seq >= lines.length) throw new Error(`seq ${seq} out of range [0, ${lines.length})`);
  const entry = JSON.parse(lines[seq]!) as LedgerEntry;
  if (entry.seq !== seq) throw new Error(`ledger line ${seq} has seq ${entry.seq} — verify the ledger first`);
  if (SYSTEM_TYPES.has(entry.type)) {
    throw new Error(`refusing to redact ${entry.type} entry — its payload is required for verification`);
  }
  if (entry.payload === undefined) throw new Error(`entry ${seq} is already redacted`);
  delete entry.payload;
  lines[seq] = JSON.stringify(entry);
  const tmpPath = path + '.redact-tmp';
  writeFileSync(tmpPath, lines.join('\n') + '\n');
  renameSync(tmpPath, path);
  return entry;
}

export async function runRedact(argv: string[]): Promise<void> {
  const { positionals } = parseArgs({ args: argv, allowPositionals: true, options: {} });
  const [dir, seqStr] = positionals;
  if (dir === undefined || seqStr === undefined || !/^\d+$/.test(seqStr)) {
    process.stderr.write('attestor: usage: attestor redact <ledger-dir> <seq>\n');
    process.exit(2);
  }
  const entry = redactEntry(dir, Number(seqStr));
  process.stdout.write(
    `redacted payload of entry ${entry.seq} (${entry.type})\n` +
      `  salted commitment retained: ${entry.payload_hash}\n` +
      `  chain, signatures, Merkle roots and anchors remain valid — run: attestor verify ${dir}\n`,
  );
}
