// P-256 recorder keys: PKCS#8 PEM on disk (0600), key_id = first 16 hex of
// SHA256(SPKI DER). P-256 (not Ed25519) because Rekor hashedrekord verifies
// over a pre-hashed digest, which pure Ed25519 cannot do (rekor#851).
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
} from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export interface KeyPair {
  keyId: string;
  privateKey: KeyObject;
  publicKey: KeyObject;
  publicPem: string;
}

export function attestorHome(): string {
  return process.env.ATTESTOR_HOME ?? join(homedir(), '.attestor');
}

export function keysDir(home: string = attestorHome()): string {
  return join(home, 'keys');
}

export function keyIdOf(publicKey: KeyObject): string {
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(spki).digest('hex').slice(0, 16);
}

function toKeyPair(privateKey: KeyObject): KeyPair {
  const publicKey = createPublicKey(privateKey);
  return {
    keyId: keyIdOf(publicKey),
    privateKey,
    publicKey,
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

export function generateKey(
  home: string = attestorHome(),
  passphrase?: string,
): KeyPair {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const pair = toKeyPair(privateKey);
  const dir = keysDir(home);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const pem = passphrase
    ? privateKey.export({
        type: 'pkcs8',
        format: 'pem',
        cipher: 'aes-256-cbc',
        passphrase,
      })
    : privateKey.export({ type: 'pkcs8', format: 'pem' });
  writeFileSync(join(dir, `${pair.keyId}.pem`), pem, { mode: 0o600 });
  writeFileSync(join(dir, `${pair.keyId}.pub`), pair.publicPem, { mode: 0o644 });
  return pair;
}

/** Key ids, oldest first (mtime order) — the last one is the active key. */
export function listKeyIds(home: string = attestorHome()): string[] {
  const dir = keysDir(home);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith('.pem') && f !== 'rekor-pub.pem')
    .map((f) => ({ id: f.slice(0, -'.pem'.length), mtime: statSync(join(dir, f)).mtimeMs }))
    .sort((a, b) => a.mtime - b.mtime)
    .map((k) => k.id);
}

export function loadKey(
  home: string = attestorHome(),
  keyId?: string,
  passphrase?: string,
): KeyPair {
  const ids = listKeyIds(home);
  const id = keyId ?? ids[ids.length - 1];
  if (!id) throw new Error(`no keys found in ${keysDir(home)} — run: attestor keys init`);
  const pem = readFileSync(join(keysDir(home), `${id}.pem`), 'utf8');
  const privateKey = passphrase
    ? createPrivateKey({ key: pem, passphrase })
    : createPrivateKey(pem);
  const pair = toKeyPair(privateKey);
  if (pair.keyId !== id) {
    throw new Error(`key file ${id}.pem contains key with id ${pair.keyId}`);
  }
  return pair;
}

export function publicKeyFromPem(pem: string): KeyObject {
  return createPublicKey(pem);
}
