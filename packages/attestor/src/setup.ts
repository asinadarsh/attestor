// `attestor setup` — get from "installed" to "recording" without reading docs.
//
// Interactive only where a real decision exists: which config to edit, which
// servers to wrap, whether to write. Everything else proceeds on its own. When
// stdin is not a TTY (piped installer, CI, Docker) it never prompts and never
// blocks: with --yes it applies the safe defaults, without it prints the plan
// and exits, so an unattended run can't silently rewrite someone's config.
import { createInterface } from 'node:readline/promises';
import { copyFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir, platform } from 'node:os';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { attestorHome, generateKey, keysDir, listKeyIds } from './keys.ts';
import { attestorInvocation, claudeDesktopConfigPaths, wrapConfig } from './mcpconfig.ts';

const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RESET = '\x1b[0m';

function color(code: string, s: string): string {
  return process.stdout.isTTY ? `${code}${s}${RESET}` : s;
}

function say(s = ''): void {
  process.stdout.write(s + '\n');
}

function step(n: number, total: number, title: string): void {
  say('');
  say(color(BOLD, `[${n}/${total}] ${title}`));
}

const ok = (s: string) => say(`  ${color(GREEN, '✔')} ${s}`);
const info = (s: string) => say(`  ${color(DIM, '·')} ${color(DIM, s)}`);
const warn = (s: string) => say(`  ${color(YELLOW, '!')} ${s}`);

interface McpServerDef {
  command: string;
  args?: string[];
  [k: string]: unknown;
}

interface ConfigTarget {
  path: string;
  label: string;
  /** Every mcpServers map in the file, with the servers it holds. */
  groups: { servers: Record<string, McpServerDef>; scope: string }[];
  json: Record<string, unknown>;
}

/** Every MCP config we know how to edit, that exists and has servers in it. */
export function findConfigs(cwd = process.cwd()): ConfigTarget[] {
  const out: ConfigTarget[] = [];
  const consider = (path: string, label: string): void => {
    if (!existsSync(path)) return;
    let json: Record<string, unknown>;
    try {
      json = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
    } catch {
      return; // unparsable — leave it alone
    }
    const groups: ConfigTarget['groups'] = [];
    const top = json.mcpServers as Record<string, McpServerDef> | undefined;
    if (top && Object.keys(top).length > 0) groups.push({ servers: top, scope: 'global' });
    // Claude Code keeps per-project servers under projects["<abs path>"].mcpServers
    const projects = json.projects as Record<string, { mcpServers?: Record<string, McpServerDef> }> | undefined;
    for (const [proj, def] of Object.entries(projects ?? {})) {
      if (def?.mcpServers && Object.keys(def.mcpServers).length > 0) {
        groups.push({ servers: def.mcpServers, scope: proj });
      }
    }
    if (groups.length > 0) out.push({ path, label, groups, json });
  };

  consider(resolve(cwd, '.mcp.json'), 'this project (.mcp.json)');
  for (const p of claudeDesktopConfigPaths()) consider(p, 'Claude Desktop');
  consider(join(homedir(), '.claude.json'), 'Claude Code');
  return out;
}

function stdioServers(group: { servers: Record<string, McpServerDef> }): string[] {
  return Object.entries(group.servers)
    .filter(([, d]) => typeof d?.command === 'string' && d.command !== '')
    .map(([name]) => name);
}

export async function runSetup(argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: {
      yes: { type: 'boolean', short: 'y', default: false },
      config: { type: 'string' },
      'dry-run': { type: 'boolean', default: false },
    },
  });
  const isTty = Boolean(process.stdin.isTTY && process.stdout.isTTY);
  const interactive = isTty && !values.yes;
  const rl = interactive ? createInterface({ input: process.stdin, output: process.stdout }) : undefined;

  const confirm = async (question: string, def = true): Promise<boolean> => {
    if (!rl) return values.yes;
    const hint = def ? 'Y/n' : 'y/N';
    const a = (await rl.question(`  ${question} [${hint}] `)).trim().toLowerCase();
    if (a === '') return def;
    return a.startsWith('y');
  };

  try {
    say(color(BOLD, 'attestor setup'));
    info(`${platform()} · node ${process.version} · home ${attestorHome()}`);
    if (!interactive && !values.yes) {
      info('not a terminal — showing the plan only; re-run with --yes to apply');
    }

    const TOTAL = 3;

    // ---- 1. Node version -------------------------------------------------
    step(1, TOTAL, 'Checking prerequisites');
    const major = Number(process.versions.node.split('.')[0]);
    if (Number.isFinite(major) && major < 24) {
      warn(`Node ${process.version} is too old — attestor needs Node 24+ (it runs TypeScript directly).`);
      say('');
      say('  Install Node 24: https://nodejs.org/en/download');
      process.exitCode = 2;
      return;
    }
    ok(`Node ${process.version}`);

    // ---- 2. Recorder key -------------------------------------------------
    step(2, TOTAL, 'Recorder signing key');
    const existing = listKeyIds();
    if (existing.length > 0) {
      ok(`using existing key ${existing[existing.length - 1]} in ${keysDir()}`);
    } else if (values['dry-run'] || (!interactive && !values.yes)) {
      info(`would generate a P-256 signing key in ${keysDir()}`);
    } else {
      const pair = generateKey();
      ok(`generated P-256 key ${pair.keyId}`);
      info(`private key: ${keysDir()}/${pair.keyId}.pem`);
      if (platform() === 'win32') {
        info('permissions restricted to your account with icacls');
      } else {
        info('permissions: 0600 (owner only)');
      }
      info('this key signs every entry — back it up, and never commit it');
    }

    // ---- 3. Wrap MCP servers --------------------------------------------
    step(3, TOTAL, 'Recording your MCP servers');
    const targets = values.config !== undefined
      ? findConfigsAt(values.config)
      : findConfigs();

    if (targets.length === 0) {
      info('no MCP config with servers found.');
      say('');
      say('  Nothing to wrap yet. When you have one, run this again, or wrap a server directly:');
      say(color(DIM, '    attestor wrap -- npx -y @modelcontextprotocol/server-github'));
      printNextSteps();
      return;
    }

    const invocation = attestorInvocation();
    let wroteAny = false;

    for (const target of targets) {
      const names = target.groups.flatMap(stdioServers);
      if (names.length === 0) continue;
      say('');
      say(`  ${color(BOLD, target.label)}  ${color(DIM, target.path)}`);
      for (const n of names) say(`    · ${n}`);

      const apply = values['dry-run']
        ? false
        : interactive
          ? await confirm(`Record ${names.length === 1 ? 'this server' : `these ${names.length} servers`}?`, true)
          : values.yes;

      if (!apply) {
        info(values['dry-run'] ? 'dry run — not modified' : 'skipped');
        continue;
      }

      let changed: string[] = [];
      for (const group of target.groups) {
        const res = wrapConfig({ mcpServers: group.servers }, invocation);
        changed = [...changed, ...res.changed];
        for (const s of res.skipped) info(`${s}: already recorded`);
      }
      if (changed.length === 0) {
        info('already up to date');
        continue;
      }
      copyFileSync(target.path, `${target.path}.bak`);
      writeFileSync(target.path, JSON.stringify(target.json, null, 2) + '\n');
      ok(`recording ${changed.join(', ')}`);
      info(`backup: ${target.path}.bak`);
      wroteAny = true;
    }

    if (wroteAny) {
      say('');
      say(`  ${color(YELLOW, 'Restart your MCP client')} so it picks up the new configuration.`);
    }
    printNextSteps();
  } finally {
    rl?.close();
  }
}

function findConfigsAt(path: string): ConfigTarget[] {
  if (!existsSync(path)) {
    warn(`no such config: ${path}`);
    return [];
  }
  const json = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
  const groups: ConfigTarget['groups'] = [];
  const top = json.mcpServers as Record<string, McpServerDef> | undefined;
  if (top) groups.push({ servers: top, scope: 'global' });
  return groups.length > 0 ? [{ path, label: 'config', groups, json }] : [];
}

function printNextSteps(): void {
  say('');
  say(color(BOLD, 'Next'));
  say(`  ${color(DIM, 'see it work:')}      attestor demo tamper`);
  say(`  ${color(DIM, 'check a ledger:')}   attestor verify ${join(attestorHome(), 'ledgers', '<name>')}`);
  say(`  ${color(DIM, 'evidence pack:')}    attestor export ${join(attestorHome(), 'ledgers', '<name>')}`);
  say('');
  say(color(DIM, '  Undo: restore the .bak file next to any config that was changed.'));
}
