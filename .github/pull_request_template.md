## What and why

<!-- The diff shows what changed; this is for why. -->

## Checks

- [ ] `npm test` passes
- [ ] `npm run build` passes (the test runner strips types without checking them, so this is what typechecks)
- [ ] If this touches verification (`verify.ts`, `ledger.ts`, `merkle.ts`, `rekor.ts`), there is a test in `test/tamper.test.ts` that fails without the change
- [ ] If this changes what the tool proves or does not prove, the README's threat model and honest-limits section say so
