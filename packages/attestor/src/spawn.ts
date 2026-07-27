// Cross-platform child launch for the stdio proxy.
//
// On Windows the command is almost always `npx …`, which is a `.cmd` shim.
// Since the CVE-2024-27980 hardening, Node refuses to spawn `.cmd`/`.bat`
// without a shell, so those must go through `cmd.exe` — and everything handed
// to `cmd.exe` has to be escaped by hand, because `shell: true` would let a
// server name containing `&` or `|` run arbitrary commands.
//
// The escaping below follows cross-spawn (MIT), which is what the MCP SDK
// itself uses, so wrapped and unwrapped servers launch identically. It is
// reimplemented rather than depended on to keep the runtime dependency
// surface at one package — the escaping is ~30 lines and is unit-tested
// against the same cases on every platform.
import { spawn, type ChildProcessByStdio } from 'node:child_process';
import type { Readable, Writable } from 'node:stream';
import { existsSync, statSync } from 'node:fs';
import { delimiter, join, normalize } from 'node:path';

/** cmd.exe metacharacters, escaped with `^`. See http://www.robvanderwoude.com/escapechars.php */
const META_CHARS = /([()\][%!^"`<>&|;, *?])/g;

export function escapeCommand(arg: string): string {
  return arg.replace(META_CHARS, '^$1');
}

/**
 * Quote one argument for `cmd.exe /c`. Based on https://qntm.org/cmd:
 * double up backslashes before a quote (or at the end), escape the quote,
 * wrap the whole thing, then escape shell metacharacters.
 */
export function escapeArgument(arg: string, doubleEscapeMetaChars = false): string {
  let out = String(arg);
  out = out.replace(/(?=(\\+?)?)\1"/g, '$1$1\\"');
  out = out.replace(/(?=(\\+?)?)\1$/, '$1$1');
  out = `"${out}"`;
  out = out.replace(META_CHARS, '^$1');
  if (doubleEscapeMetaChars) out = out.replace(META_CHARS, '^$1');
  return out;
}

/** A `.cmd` in node_modules/.bin re-invokes cmd.exe, so its args need escaping twice. */
const CMD_SHIM = /node_modules[\\/]\.bin[\\/][^\\/]+\.cmd$/i;
/** Real executables can be spawned directly; anything else needs a shell. */
const DIRECTLY_EXECUTABLE = /\.(?:com|exe)$/i;

/** Resolve a command against PATH, honoring PATHEXT on Windows. */
export function resolveCommand(
  command: string,
  env: NodeJS.ProcessEnv = process.env,
  osPlatform: NodeJS.Platform = process.platform,
): string | undefined {
  const isWin = osPlatform === 'win32';
  // PATHEXT is conventionally uppercase while files on disk are lowercase.
  // NTFS is normally case-insensitive so it does not matter there, but it does
  // on case-sensitive volumes (and when these tests run on Linux), so probe both.
  const exts = isWin
    ? [
        ...new Set(
          (env.PATHEXT ?? '.COM;.EXE;.BAT;.CMD')
            .split(';')
            .filter(Boolean)
            .flatMap((e) => [e, e.toLowerCase(), e.toUpperCase()]),
        ),
      ]
    : [''];
  const hasDirPart = command.includes('/') || (isWin && command.includes('\\'));
  const dirs = hasDirPart ? [''] : (env.PATH ?? '').split(delimiter).filter(Boolean);

  for (const dir of dirs) {
    const base = dir === '' ? command : join(dir, command);
    // an explicit extension wins over PATHEXT probing
    if (isFile(base) && (!isWin || /\.[^\\/.]+$/.test(base))) return base;
    for (const ext of exts) {
      const candidate = base + ext;
      if (isFile(candidate)) return candidate;
    }
    if (!isWin && isFile(base)) return base;
  }
  return undefined;
}

function isFile(p: string): boolean {
  try {
    return existsSync(p) && statSync(p).isFile();
  } catch {
    return false;
  }
}

/**
 * Characters that cannot be escaped for `cmd.exe` under any quoting scheme
 * (see the BatBadBut research). An argument containing one of these cannot be
 * passed safely, so it is refused rather than silently mangled or injected.
 */
const UNESCAPABLE = /[\r\n\0]/;

export class UnsafeArgumentError extends Error {}

export interface SpawnPlan {
  command: string;
  args: string[];
  windowsVerbatimArguments: boolean;
  /** The resolved on-disk path, when we could find it (diagnostics only). */
  resolved?: string;
}

/**
 * Decide how to launch `command args…`. Pure so it can be unit-tested for
 * Windows behavior from any platform.
 */
export function planSpawn(
  command: string,
  args: string[],
  osPlatform: NodeJS.Platform = process.platform,
  env: NodeJS.ProcessEnv = process.env,
): SpawnPlan {
  if (osPlatform !== 'win32') {
    return { command, args, windowsVerbatimArguments: false };
  }
  const resolved = resolveCommand(command, env, osPlatform);
  // Unresolvable commands are passed through untouched so the caller sees
  // Node's own ENOENT rather than a confusing cmd.exe error.
  if (resolved !== undefined && DIRECTLY_EXECUTABLE.test(resolved)) {
    return { command, args, windowsVerbatimArguments: false, resolved };
  }
  for (const a of [command, ...args]) {
    if (UNESCAPABLE.test(a)) {
      throw new UnsafeArgumentError(
        'attestor: refusing to launch a Windows command whose arguments contain a newline or NUL byte — ' +
          'those cannot be escaped for cmd.exe, so passing them through could execute something else',
      );
    }
  }
  const doubleEscape = resolved !== undefined && CMD_SHIM.test(resolved);
  const line = [escapeCommand(normalize(command)), ...args.map((a) => escapeArgument(a, doubleEscape))].join(' ');
  return {
    command: env.comspec ?? env.ComSpec ?? 'cmd.exe',
    args: ['/d', '/s', '/c', `"${line}"`],
    windowsVerbatimArguments: true,
    ...(resolved !== undefined && { resolved }),
  };
}

/**
 * Launch the wrapped server. stdin/stdout are pipes (the relay owns them);
 * stderr is inherited so the server's own logging reaches the user unchanged.
 */
export type ServerProcess = ChildProcessByStdio<Writable, Readable, null>;

export function spawnServer(command: string, args: string[]): ServerProcess {
  const plan = planSpawn(command, args);
  // stdin/stdout are pipes and stderr is inherited, so `stdin`/`stdout` are
  // always present — the typed return says so, instead of every caller
  // re-checking for null.
  return spawn(plan.command, plan.args, {
    stdio: ['pipe', 'pipe', 'inherit'],
    shell: false,
    windowsVerbatimArguments: plan.windowsVerbatimArguments,
  }) as ServerProcess;
}
