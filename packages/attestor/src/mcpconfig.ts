// Reading and rewriting MCP client configuration. Kept separate from cli.ts so
// that both the CLI and the setup wizard can use it without a circular import
// (cli.ts has a top-level dispatch, and importing it from a module it imports
// deadlocks the ESM graph).
import { existsSync } from 'node:fs';
import { homedir, platform } from 'node:os';
import { fileURLToPath } from 'node:url';
import { delimiter, dirname, join } from 'node:path';

export interface McpServerDef {
  command: string;
  args?: string[];
  [k: string]: unknown;
}

/** Already wrapped? Match the binary in any spelling, or an existing wrap argv. */
function isAlreadyWrapped(def: McpServerDef): boolean {
  const cmd = (def.command ?? '').replace(/\\/g, '/');
  const base = cmd.slice(cmd.lastIndexOf('/') + 1).toLowerCase();
  if (base === 'attestor' || base === 'attestor.cmd' || base === 'attestor.exe') return true;
  const args = def.args ?? [];
  // `npx attestor wrap …`, `<node> …/attestor/dist/cli.js wrap …`
  return args.some((a, i) => a === 'wrap' && args.slice(0, i).some((p) => /attestor/i.test(p)));
}

/** Claude Desktop's config location, per platform. */
export function claudeDesktopConfigPaths(): string[] {
  const file = 'claude_desktop_config.json';
  switch (platform()) {
    case 'darwin':
      return [join(homedir(), 'Library', 'Application Support', 'Claude', file)];
    case 'win32': {
      const appData = process.env.APPDATA ?? join(homedir(), 'AppData', 'Roaming');
      return [join(appData, 'Claude', file)];
    }
    default: {
      const xdg = process.env.XDG_CONFIG_HOME ?? join(homedir(), '.config');
      return [join(xdg, 'Claude', file)];
    }
  }
}

/** Slugify a server name into a filesystem-safe ledger directory name. */
function ledgerSlug(name: string): string {
  const slug = name.toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '');
  return slug === '' ? 'server' : slug;
}

/**
 * How the MCP client should invoke attestor. A bare `attestor` only works if
 * the package is globally installed; from a git clone it is not on PATH, and
 * writing it anyway produces a config that silently kills the wrapped server.
 * So: use `attestor` only when it really resolves, else this exact Node
 * binary plus the absolute path to this CLI.
 */
export function attestorInvocation(): { command: string; prefixArgs: string[] } {
  if (whichAttestor() !== undefined) return { command: 'attestor', prefixArgs: [] };
  return { command: process.execPath, prefixArgs: [cliEntryPath()] };
}

/**
 * Absolute path to the CLI entry point. This module is a sibling of it in both
 * layouts (src/*.ts when run from source, dist/*.js once built), so derive the
 * path from this file rather than from import.meta.url directly — that would
 * point at this module, which is not runnable as a command.
 */
export function cliEntryPath(): string {
  const self = fileURLToPath(import.meta.url);
  const ext = self.endsWith('.ts') ? '.ts' : '.js';
  return join(dirname(self), `cli${ext}`);
}

/** Resolve `attestor` on PATH, honoring PATHEXT on Windows. */
function whichAttestor(): string | undefined {
  const exts = platform() === 'win32'
    ? (process.env.PATHEXT ?? '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean)
    : [''];
  for (const dir of (process.env.PATH ?? '').split(delimiter).filter(Boolean)) {
    for (const ext of exts) {
      const candidate = join(dir, `attestor${ext}`);
      if (existsSync(candidate)) return candidate;
    }
  }
  return undefined;
}

export function wrapConfig(
  config: { mcpServers?: Record<string, McpServerDef> },
  invocation: { command: string; prefixArgs: string[] } = attestorInvocation(),
): {
  changed: string[];
  skipped: string[];
} {
  const changed: string[] = [];
  const skipped: string[] = [];
  for (const [name, def] of Object.entries(config.mcpServers ?? {})) {
    if (isAlreadyWrapped(def)) {
      skipped.push(name);
      continue;
    }
    // Each server gets its OWN ledger: the single-writer lockfile means a
    // shared default dir would let the first server start and every other one
    // die with "ledger locked by pid N".
    def.args = [
      ...invocation.prefixArgs,
      'wrap',
      '--ledger-name',
      ledgerSlug(name),
      '--',
      def.command,
      ...(def.args ?? []),
    ];
    def.command = invocation.command;
    changed.push(name);
  }
  return { changed, skipped };
}

