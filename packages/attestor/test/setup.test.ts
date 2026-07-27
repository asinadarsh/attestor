// The setup wizard's load-bearing property: it rewrites MCP configs, so an
// unattended run must never do that silently, and an attended one must produce
// a config that actually launches.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';

const exec = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'src', 'cli.ts');

function workspace(): { dir: string; config: string; env: NodeJS.ProcessEnv } {
  const dir = mkdtempSync(join(tmpdir(), 'attestor-setup-'));
  const config = join(dir, '.mcp.json');
  writeFileSync(
    config,
    JSON.stringify({
      mcpServers: {
        github: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'], env: { GITHUB_TOKEN: 'ghp_secret' } },
      },
    }),
  );
  return { dir, config, env: { ...process.env, ATTESTOR_HOME: join(dir, 'home') } };
}

test('non-interactive without --yes: shows the plan and changes nothing', async () => {
  const { dir, config, env } = workspace();
  const before = readFileSync(config, 'utf8');
  const { stdout } = await exec(process.execPath, [CLI, 'setup', '--config', config], { cwd: dir, env });

  assert.match(stdout, /not a terminal/);
  assert.match(stdout, /github/);
  assert.equal(readFileSync(config, 'utf8'), before, 'config must be untouched');
  assert.ok(!existsSync(join(dir, 'home', 'keys')), 'no key generated either');
});

test('--yes: installs a key and rewrites the config to a launchable command', async () => {
  const { dir, config, env } = workspace();
  await exec(process.execPath, [CLI, 'setup', '--yes', '--config', config], { cwd: dir, env });

  const after = JSON.parse(readFileSync(config, 'utf8')) as {
    mcpServers: Record<string, { command: string; args: string[]; env?: Record<string, string> }>;
  };
  const gh = after.mcpServers.github!;
  // whatever it wrote must be runnable as-is
  if (gh.command !== 'attestor') {
    assert.ok(isAbsolute(gh.command) && existsSync(gh.command), `command must exist: ${gh.command}`);
    assert.ok(existsSync(gh.args[0]!), `cli entry must exist: ${gh.args[0]}`);
  }
  assert.ok(gh.args.includes('wrap'));
  // the original server must survive intact, after the `--`
  const sep = gh.args.indexOf('--');
  assert.deepEqual(gh.args.slice(sep + 1), ['npx', '-y', '@modelcontextprotocol/server-github']);
  assert.deepEqual(gh.env, { GITHUB_TOKEN: 'ghp_secret' }, 'env must be preserved, not rewritten');
  assert.ok(existsSync(`${config}.bak`), 'a backup must be left behind');
  assert.equal(
    JSON.parse(readFileSync(`${config}.bak`, 'utf8')).mcpServers.github.command,
    'npx',
    'backup holds the original',
  );
});

test('re-running is idempotent — no double wrapping', async () => {
  const { dir, config, env } = workspace();
  await exec(process.execPath, [CLI, 'setup', '--yes', '--config', config], { cwd: dir, env });
  const once = readFileSync(config, 'utf8');
  const { stdout } = await exec(process.execPath, [CLI, 'setup', '--yes', '--config', config], { cwd: dir, env });
  assert.equal(readFileSync(config, 'utf8'), once, 'second run must not change anything');
  assert.match(stdout, /already recorded|already up to date/);
});

test('--dry-run never writes', async () => {
  const { dir, config, env } = workspace();
  const before = readFileSync(config, 'utf8');
  const { stdout } = await exec(process.execPath, [CLI, 'setup', '--dry-run', '--yes', '--config', config], { cwd: dir, env });
  assert.equal(readFileSync(config, 'utf8'), before);
  assert.match(stdout, /dry run/);
});
