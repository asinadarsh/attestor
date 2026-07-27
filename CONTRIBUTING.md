# Contributing to attestor

Thanks for looking. This is a security tool, so the bar for *evidence* is
higher than the bar for *code* — a small change with a test that fails without
it is worth more here than a large one without.

## Getting set up

```sh
git clone https://github.com/asinadarsh/attestor && cd attestor
npm install          # also builds; the CLI needs no separate build step
npm test             # ~98 tests, should take well under a minute
```

**Node 24 or newer is required.** The CLI runs TypeScript directly using Node's
native type stripping — there is no transpile step in development, and older
Node will fail immediately.

Run the CLI from source without installing anything:

```sh
node packages/attestor/src/cli.ts demo tamper
node packages/attestor/src/cli.ts verify examples/pack-2026-07
```

### One test skips on purpose

`npm test` reports 3 skipped. That is expected, not broken:

- The live Rekor test only runs with `ATTESTOR_LIVE=1` (it writes a real entry
  to Sigstore's public log, so it stays opt-in).
- Two Windows-only tests skip on Linux and macOS.

```sh
ATTESTOR_LIVE=1 npm test   # includes the live-network test
```

## What the project is trying to be

A few constraints that explain most review comments:

**One runtime dependency.** `canonicalize` (the RFC 8785 implementation) is the
only one, and the pitch depends on that staying true. Dev dependencies are
fine. If something genuinely needs a new runtime dependency, open an issue
first — it is a design conversation, not a code-review nit.

**The exit code is the product.** `verify` returns 0 verified, 1 tamper, 2
usage/IO error, 3 Rekor unreachable, 4 chain intact but anchors unauthenticated.
Tools and CI read that number. Any change that could make a tampered ledger
report success is the most serious kind of bug this project can have.

**Say what is not proven.** The README's honest-limits section and the threat
model are load-bearing, not marketing. If a change narrows or widens what the
tool actually demonstrates, the change is incomplete until those say so too.

## Changes that touch verification

If you touch `verify.ts`, `ledger.ts`, `merkle.ts`, or `rekor.ts`, please add a
test to `test/tamper.test.ts` in the existing style: construct the attack, then
assert the exit code. The suite is written as an attack matrix on purpose — it
is the part that would catch a regression that silently weakens the guarantee.

A test that fails before your fix and passes after it is the most persuasive
thing you can put in a pull request.

## Platform notes

CI runs the full suite, the evidence-pack checks and the installers on Linux,
macOS and Windows. Two things that only matter on Windows and are easy to break
without noticing:

- `.cmd` and `.bat` cannot be spawned without a shell since the
  CVE-2024-27980 hardening, and `npx` is a `.cmd` shim. `src/spawn.ts` handles
  this with hand-escaped arguments — never `shell: true`, which would let a
  server argument containing `&` run arbitrary commands.
- POSIX mode bits do nothing on NTFS, so key permissions go through `icacls`.

`planSpawn` takes the platform as a parameter, so Windows behavior is testable
from any machine — see `test/spawn.test.ts`.

## Pull requests

- Branch from `main`, keep the diff focused on one thing.
- `npm test` green, and `npm run build` (the build is what typechecks — the
  test runner strips types without checking them).
- Explain *why* in the description. The what is visible in the diff.

No CLA. Contributions are under the project's MIT license.

## Reporting a vulnerability

Please do not open a public issue for a security problem — see
[SECURITY.md](SECURITY.md) for how to report privately, and for what is in and
out of scope.

## Good places to start

Issues tagged [`good first issue`](https://github.com/asinadarsh/attestor/labels/good%20first%20issue)
are scoped to be self-contained. Issues tagged
[`help wanted`](https://github.com/asinadarsh/attestor/labels/help%20wanted)
are larger and worth a comment before you start, so two people don't build the
same thing.

If something in the docs was wrong or confusing, that is a real bug and a
welcome pull request.
